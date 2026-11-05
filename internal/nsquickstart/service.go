// Package nsquickstart is Fortik's NetSuite MCP transport: connections to a
// NetSuite MCP server, one per tenant (logical integration), of two kinds:
//
//   - netsuite_quickstart: the NetSuite QuickStart MCP server, with a
//     personal access token;
//   - netsuite_mcp: a full NetSuite account's AI Connector Service, with
//     OAuth 2.0 authorization code + PKCE tokens a NetSuite user grants
//     Fortik (oauth.go).
//
// It checks each connection (initialize, notifications/initialized,
// tools/list; never a tool call), records the discovered tools, and serves
// Fortik's MCP endpoint for agents (proxy.go): every tools/call is decided
// as system netsuite, transport mcp, before Fortik forwards it with the
// credential it holds.
//
// Credentials are read from the secret store and sent only to the
// connection's endpoint, which must be a permitted host (config
// mcp_upstreams). They are never logged, stored in Postgres, written to the
// Diary or returned by the API.
package nsquickstart

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/authz"
	"fortik/internal/config"
	"fortik/internal/diary"
	"fortik/internal/integrations"
	"fortik/internal/mcpclient"
	"fortik/internal/secrets"
	"fortik/internal/undo"
)

// The transport is MCP, the business system NetSuite. IntegrationKey is the
// legacy single QuickStart connection (logical integration
// netsuite:quickstart).
const (
	IntegrationKey = integrations.SystemNetSuiteQuickStart
	System         = "netsuite"
	Transport      = integrations.TransportMCP
)

// Auth types of an MCP connection.
const (
	AuthPAT         = "personal_access_token"
	AuthOAuth       = integrations.AuthOAuthCode
	AuthClientCreds = integrations.AuthClientCreds
	AuthBearer      = integrations.AuthBearer
)

// Connection states. Stored states come from a live check; StateNotConfigured
// and StateSavedNotTested are derived.
const (
	StateNotConfigured   = "not_configured"
	StateSavedNotTested  = "saved_not_tested"
	StateConnected       = "connected"
	StateConnectedLimit  = "connected_limited" // connected, but required capabilities are missing
	StateAuthFailed      = "auth_failed"
	StateTokenExpired    = "token_expired" // only when the server's message says expired or revoked
	StatePermission      = "permission_denied"
	StateInitFailed      = "mcp_init_failed"
	StateDiscoveryFailed = "tool_discovery_failed"
	StateUnavailable     = "unavailable"
	StateNotPermitted    = "endpoint_not_permitted"
	StateAuthRequired    = "authorization_required" // OAuth: no NetSuite user has authorized Fortik yet
)

var stateLabels = map[string]string{
	StateNotConfigured:   "Not configured",
	StateSavedNotTested:  "Configuration saved but not tested",
	StateConnected:       "Connected",
	StateConnectedLimit:  "Connected, but required capabilities are unavailable",
	StateAuthFailed:      "Authentication failed",
	StateTokenExpired:    "Token expired or revoked",
	StatePermission:      "Permission denied",
	StateInitFailed:      "MCP initialization failed",
	StateDiscoveryFailed: "Tool discovery failed",
	StateUnavailable:     "Temporarily unavailable",
	StateNotPermitted:    "Endpoint not permitted",
	StateAuthRequired:    "Authorization required",
}

// Diary event types.
const (
	EventToolsChanged = "mcp.tools.changed"
	EventForgotten    = "mcp.connection.forgotten"
)

// RevokeInstructions: disconnecting a QuickStart connection does not revoke
// the token; RevokeInstructionsOAuth: disconnecting an AI Connector Service
// connection asks NetSuite to revoke the grant (the result says whether it did).
const (
	RevokeInstructions      = "Disconnecting removes the token from Fortik only; it does not revoke it in QuickStart. To revoke it: QuickStart > Menu > Administration > QuickStart settings > Personal access tokens > revoke the token (e.g. \"Fortik\")."
	RevokeInstructionsOAuth = "Disconnecting asks NetSuite to revoke Fortik's OAuth grant (its refresh token and access tokens) and reports whether NetSuite confirmed it. The integration record and the user's role are unchanged."
)

// CallTimeout bounds one agent tool call (reports can take a while).
const CallTimeout = 90 * time.Second

// CheckTimeout bounds one live check. It is shorter than the integrations
// handler's test timeout (integrations.TestTimeout) so the outcome is always
// recorded before the handler gives up.
const CheckTimeout = 12 * time.Second

// Settings is one MCP connection's configuration, with its credential.
type Settings struct {
	Key           string // the connection key, e.g. netsuite_quickstart or netsuite_mcp:acme
	System        string // netsuite_quickstart | netsuite_mcp
	IntegrationID string // the logical integration, e.g. netsuite:acme
	Auth          string // AuthPAT | AuthOAuth

	Name           string
	TenantLabel    string
	Endpoint       string
	TokenExpiresOn string
	// Token is the PAT, or (OAuth) the current access token once bearer has
	// filled it in.
	Token   string
	Version time.Time // integrations.updated_at

	// OAuth.
	AccountID    string // the account (NetSuite) or host (others) tokens are bound to
	ClientID     string
	ClientSecret string // confidential clients only
	RedirectURI  string
	Scope        string
	APIBase      string // netsuite_mcp: https://<account>.suitetalk.api.netsuite.com, or a test override
	AuthBase     string // netsuite_mcp: https://<account>.app.netsuite.com, or the same test override
	AuthorizeURL string
	TokenURL     string
	RevokeURL    string // empty: the grant cannot be revoked by Fortik
}

// accountHost is NetSuite's host form of an account id (1234567_SB1 ->
// 1234567-sb1).
func accountHost(account string) string {
	return strings.ReplaceAll(strings.ToLower(account), "_", "-")
}

func settingsFrom(r integrations.Resolved) (Settings, error) {
	str := func(k string) string { v, _ := r.ConfigMap[k].(string); return strings.TrimSpace(v) }
	st := Settings{Key: r.Key, System: r.System, IntegrationID: r.IntegrationID, Version: r.UpdatedAt}
	if st.Key == "" {
		st.Key, st.System = IntegrationKey, integrations.SystemNetSuiteQuickStart
	}
	if st.IntegrationID == "" {
		_, st.IntegrationID, _ = integrations.LogicalID(st.Key)
	}
	switch st.System {
	case integrations.SystemNetSuiteMCP:
		st.Auth = AuthOAuth
		st.AccountID, st.ClientID, st.RedirectURI, st.Scope = str("account_id"), str("client_id"), str("redirect_uri"), str("scope")
		st.Name, st.TenantLabel = "NetSuite "+st.AccountID, st.AccountID
		if st.AccountID == "" || st.ClientID == "" || st.RedirectURI == "" {
			return st, fmt.Errorf("%w: account_id, client_id and redirect_uri are required", integrations.ErrNotConfigured)
		}
		if st.Scope == "" {
			st.Scope = "mcp"
		}
		st.APIBase = strings.TrimRight(str("api_base"), "/")
		st.AuthBase = st.APIBase
		if st.APIBase == "" {
			st.APIBase = "https://" + accountHost(st.AccountID) + ".suitetalk.api.netsuite.com"
			st.AuthBase = "https://" + accountHost(st.AccountID) + ".app.netsuite.com"
		}
		tools := str("tools_path")
		if tools == "" {
			tools = "all"
		}
		st.Endpoint = st.APIBase + "/services/mcp/v1/" + tools
		st.AuthorizeURL, st.TokenURL, st.RevokeURL = st.AuthBase+authorizePath, st.APIBase+tokenPath, st.APIBase+revokePath
		return st, nil
	case integrations.SystemSalesforceMCP, integrations.SystemServiceNowMCP, integrations.SystemSAPMCP:
		return genericSettings(st, r, str)
	default:
		st.Auth = AuthPAT
		st.Name, st.TenantLabel, st.Endpoint = str("name"), str("tenant_label"), str("endpoint_url")
		st.TokenExpiresOn, st.Token = str("token_expires_on"), r.Secrets["personal_access_token"]
		transport, auth := str("transport"), str("auth_type")
		if st.Endpoint == "" {
			st.Endpoint = integrations.QuickStartEndpoint
		}
		if st.Token == "" {
			return st, fmt.Errorf("%w: personal access token is not set", integrations.ErrNotConfigured)
		}
		if transport != "" && transport != "streamable_http" || auth != "" && auth != AuthPAT {
			return st, fmt.Errorf("%w: only Streamable HTTP with a personal access token is supported", integrations.ErrInvalid)
		}
		return st, nil
	}
}

// Service checks the connection, records what it learned and serves the
// status API. It is the integration's connection tester.
type Service struct {
	pool          *pgxpool.Pool
	diary         *diary.Diary
	store         *integrations.PGStore
	http          *http.Client // connection checks
	callHTTP      *http.Client // agents' tool calls
	allowed       []string
	allowLoopback bool
	lookup        func(ctx context.Context, host string) ([]net.IPAddr, error)
	log           *slog.Logger
	version       string

	running chan struct{} // one live check at a time

	upMu      sync.Mutex
	ups       map[string]*upstream // per connection key: the shared MCP session for agents' tool calls
	oauthMu   sync.Mutex
	oauthLock map[string]*sync.Mutex // per connection key: OAuth refresh (refresh tokens are one-time use)
	undo      undo.Store
	secrets   secrets.Store
	retention time.Duration

	agentEndpoint string
	mappings      map[string]*Mapping // per connection type, for the status view
}

// up returns the upstream session holder of one connection.
func (s *Service) up(key string) *upstream {
	s.upMu.Lock()
	defer s.upMu.Unlock()
	u := s.ups[key]
	if u == nil {
		u = &upstream{}
		s.ups[key] = u
	}
	return u
}

// New builds the service. version is Fortik's build version (clientInfo).
func New(pool *pgxpool.Pool, d *diary.Diary, store *integrations.PGStore, cfg config.MCPUpstreamsConfig, version string, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	s := &Service{
		pool: pool, diary: d, store: store, allowed: slices.Clone(cfg.AllowedHosts), allowLoopback: cfg.AllowLoopback,
		lookup: net.DefaultResolver.LookupIPAddr, log: log, version: version, running: make(chan struct{}, 1),
		ups: map[string]*upstream{}, oauthLock: map[string]*sync.Mutex{},
	}
	s.http = &http.Client{CheckRedirect: mcpclient.NoRedirects, Timeout: CheckTimeout, Transport: s.transport(15 * time.Second)}
	s.callHTTP = &http.Client{CheckRedirect: mcpclient.NoRedirects, Timeout: CallTimeout, Transport: s.transport(CallTimeout - 30*time.Second)}
	if store != nil {
		store.OnDelete(s.forget)
		store.OnBeforeDelete(s.beforeDisconnect)
	}
	return s
}

// SetSecrets gives the service the secret store (OAuth tokens and pending
// authorizations). EnableUndo also sets it.
func (s *Service) SetSecrets(store secrets.Store) { s.secrets = store }

// transport dials only permitted addresses and never uses a proxy.
func (s *Service) transport(headerTimeout time.Duration) *http.Transport {
	return &http.Transport{
		Proxy: nil, // a proxy would make the address check below meaningless
		DialContext: (&net.Dialer{
			Timeout: 10 * time.Second,
			// Defence in depth against DNS rebinding: the address actually
			// dialled must be permitted too.
			Control: func(_, address string, _ syscall.RawConn) error {
				host, _, err := net.SplitHostPort(address)
				if err != nil {
					return err
				}
				if r := s.addressRefused(net.ParseIP(host)); r != "" {
					return errors.New("address not permitted: " + r)
				}
				return nil
			},
		}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: headerTimeout,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
	}
}

// System implements integrations.Tester for the QuickStart connection type;
// Testers returns the testers of every MCP connection type.
func (s *Service) System() string { return IntegrationKey }

type tester struct {
	s      *Service
	system string
}

func (t tester) System() string { return t.system }
func (t tester) Test(ctx context.Context, r integrations.Resolved) error {
	return t.s.Test(ctx, r)
}

// Testers are the connection testers of every MCP connection type.
func (s *Service) Testers() []integrations.Tester {
	out := make([]integrations.Tester, 0, len(MCPSystems))
	for _, sys := range MCPSystems {
		out = append(out, tester{s, sys})
	}
	return out
}

// Test implements integrations.Tester (Integrations > Test connection): a
// live check whose outcome is recorded. The handler records the
// integration's own status from the returned error.
func (s *Service) Test(ctx context.Context, r integrations.Resolved) error {
	// Wait for a check already running (a second click must not record a
	// spurious failure); the handler's timeout bounds the wait.
	select {
	case s.running <- struct{}{}:
		defer func() { <-s.running }()
	case <-ctx.Done():
		return errors.New("another connection check was still running; try again")
	}
	return s.check(ctx, r, actorOf(ctx))
}

// check runs one live check and records it. The returned error starts with
// the state label so the integration's last_error is self-explanatory.
func (s *Service) check(ctx context.Context, r integrations.Resolved, actor string) error {
	st, err := settingsFrom(r)
	if err != nil {
		return err
	}
	start := time.Now()
	res := checkResult{endpoint: st.Endpoint}
	if reason := s.endpointRefused(ctx, st.Endpoint, st.System); reason != "" {
		res.state, res.detail = StateNotPermitted, reason
	} else if err := s.bearer(ctx, &st); err != nil {
		res.state, res.detail = oauthState(err), err.Error()
	} else {
		c := &mcpclient.Client{HTTP: s.http, Endpoint: st.Endpoint, Token: st.Token, ClientName: "fortik", ClientVersion: s.version}
		cctx, cancel := context.WithTimeout(ctx, CheckTimeout)
		d, derr := c.Discover(cctx)
		cancel()
		res.discovery = d
		if derr != nil {
			var me *mcpclient.Error
			if errors.As(derr, &me) {
				res.state, res.detail, res.httpStatus = stateOf(me.Kind), me.Step+": "+me.Detail, me.HTTPStatus
			} else {
				res.state, res.detail = StateUnavailable, derr.Error()
			}
		} else {
			res.state, res.detail = limits(d)
		}
	}
	res.detail = integrations.Sanitize(res.detail, r.Secrets)
	if st.Token != "" {
		res.detail = strings.ReplaceAll(res.detail, st.Token, "[redacted]")
	}
	res.duration = time.Since(start)
	if err := s.record(ctx, st, res, actor); err != nil {
		s.log.Error("netsuite mcp: record check", "key", st.Key, "err", err)
	}
	s.log.Info("netsuite mcp connection checked", "key", st.Key, "state", res.state, "duration_ms", res.duration.Milliseconds())
	if res.state == StateConnected {
		return nil
	}
	return errors.New(stateLabels[res.state] + ": " + res.detail)
}

func stateOf(kind string) string {
	switch kind {
	case mcpclient.KindAuthFailed:
		return StateAuthFailed
	case mcpclient.KindTokenExpired:
		return StateTokenExpired
	case mcpclient.KindPermission:
		return StatePermission
	case mcpclient.KindInitFailed:
		return StateInitFailed
	case mcpclient.KindDiscoveryFailed:
		return StateDiscoveryFailed
	default:
		return StateUnavailable
	}
}

// limits decides connected vs connected_limited: the server must declare the
// tools capability and expose at least one well-formed tool; malformed tool
// definitions are excluded and reported.
func limits(d *mcpclient.Discovery) (string, string) {
	var gaps []string
	if !d.HasTools {
		gaps = append(gaps, "the server does not declare the MCP tools capability")
	}
	if len(d.Tools) == 0 {
		gaps = append(gaps, "the server exposes no usable tools")
	}
	if n := len(d.Rejected); n > 0 {
		gaps = append(gaps, fmt.Sprintf("%d tool definition(s) are malformed and excluded", n))
	}
	if len(gaps) > 0 {
		return StateConnectedLimit, strings.Join(gaps, "; ")
	}
	return StateConnected, fmt.Sprintf("initialized (protocol %s) and listed %d tools", d.ProtocolVersion, len(d.Tools))
}

// endpointRefused checks the endpoint against the allowed hosts and the
// addresses its host resolves to. "" means permitted.
func (s *Service) endpointRefused(ctx context.Context, endpoint, system string) string {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil {
		return "the endpoint is not a valid URL"
	}
	host := strings.ToLower(u.Hostname())
	loop := isLoopbackHost(host)
	switch {
	case loop && !s.allowLoopback:
		return "loopback endpoints are allowed only when mcp_upstreams.allow_loopback is set (local fakes in development)"
	case loop:
		if u.Scheme != "http" && u.Scheme != "https" {
			return "the endpoint must use https"
		}
		return ""
	case u.Scheme != "https":
		return "the endpoint must use https"
	case !slices.Contains(s.allowed, host) && !builtinHost(system, host):
		return fmt.Sprintf("host %q is not in mcp_upstreams.allowed_hosts (%s)", clip(host, 100), strings.Join(s.allowed, ", "))
	}
	lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := s.lookup(lctx, host)
	if err != nil {
		return "" // reported by the connection attempt as unavailable
	}
	for _, a := range addrs {
		if r := s.addressRefused(a.IP); r != "" {
			return fmt.Sprintf("host %q resolves to a non-public address (%s)", clip(host, 100), r)
		}
	}
	return ""
}

// addressRefused refuses internal addresses ("" means permitted).
func (s *Service) addressRefused(ip net.IP) string {
	switch {
	case ip == nil:
		return "unparseable address"
	case ip.IsLoopback():
		if s.allowLoopback {
			return ""
		}
		return "loopback"
	case ip.IsPrivate():
		return "private"
	case ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast():
		return "link-local"
	case ip.IsUnspecified() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast():
		return "not unicast"
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 64 {
		return "carrier-grade NAT"
	}
	return ""
}

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

type checkResult struct {
	endpoint   string
	state      string
	detail     string
	httpStatus int
	discovery  *mcpclient.Discovery
	duration   time.Duration
}

type storedTool struct {
	mcpclient.Tool
	DocumentedAccess string `json:"documented_access"`
	Hash             string `json:"hash"`
}

// record stores the outcome for the checked settings version. A failed
// check keeps the tools of the last successful one. Results for settings
// that changed or were deleted during the check are dropped.
func (s *Service) record(ctx context.Context, st Settings, res checkResult, actor string) error {
	key, version := st.Key, st.Version
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var current time.Time
		err := tx.QueryRow(ctx, `SELECT updated_at FROM integrations WHERE key = $1 FOR SHARE`, key).Scan(&current)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && !current.Equal(version) {
			return nil // stale result
		}
		if err != nil {
			return err
		}
		var status any
		if res.httpStatus != 0 {
			status = res.httpStatus
		}
		ok := res.state == StateConnected || res.state == StateConnectedLimit
		if !ok {
			_, err = tx.Exec(ctx, `
				INSERT INTO mcp_connections (integration_key, config_version, state, detail, http_status, endpoint, duration_ms, last_attempt_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7, now())
				ON CONFLICT (integration_key) DO UPDATE SET config_version = $2, state = $3, detail = $4, http_status = $5,
					endpoint = $6, duration_ms = $7, last_attempt_at = now()`,
				key, version, res.state, res.detail, status, res.endpoint, res.duration.Milliseconds())
			return err
		}
		d := res.discovery
		var prevRaw []byte
		err = tx.QueryRow(ctx, `SELECT tools FROM mcp_connections WHERE integration_key = $1`, key).Scan(&prevRaw)
		first := errors.Is(err, pgx.ErrNoRows)
		if err != nil && !first {
			return err
		}
		var prev []storedTool
		_ = json.Unmarshal(prevRaw, &prev)
		tools := make([]storedTool, 0, len(d.Tools))
		names := make([]string, 0, len(d.Tools))
		for _, t := range d.Tools {
			doc := DocUndocumented
			if st.System == integrations.SystemNetSuiteQuickStart {
				doc = documentedAccess(t.Name)
			}
			tools = append(tools, storedTool{Tool: t, DocumentedAccess: doc, Hash: toolHash(t)})
			names = append(names, t.Name)
		}
		mode, basis := inferMode(names)
		if st.System != integrations.SystemNetSuiteQuickStart {
			mode, basis = ModeUnknown, "the AI Connector Service runs every tool with the authorizing NetSuite user's role; Fortik cannot read that role's permissions"
		}
		hash := setHash(tools)
		toolsJSON, _ := json.Marshal(tools)
		rejected := d.Rejected
		if rejected == nil {
			rejected = []mcpclient.Rejected{}
		}
		rejJSON, _ := json.Marshal(rejected)
		var prevHash string
		_ = tx.QueryRow(ctx, `SELECT tools_hash FROM mcp_connections WHERE integration_key = $1`, key).Scan(&prevHash)
		_, err = tx.Exec(ctx, `
			INSERT INTO mcp_connections (integration_key, config_version, state, detail, http_status, endpoint, protocol_version,
				server_name, server_version, server_instructions, capabilities, tools, rejected_tools, tools_hash,
				permission_mode, permission_basis, duration_ms, last_attempt_at, last_success_at, last_tools_sync_at)
			VALUES ($1, $2, $3, $4, NULL, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, now(), now(), now())
			ON CONFLICT (integration_key) DO UPDATE SET config_version = $2, state = $3, detail = $4, http_status = NULL,
				endpoint = $5, protocol_version = $6, server_name = $7, server_version = $8, server_instructions = $9,
				capabilities = $10, tools = $11, rejected_tools = $12, tools_hash = $13, permission_mode = $14,
				permission_basis = $15, duration_ms = $16, last_attempt_at = now(), last_success_at = now(), last_tools_sync_at = now()`,
			key, version, res.state, res.detail, res.endpoint, d.ProtocolVersion, d.ServerName, d.ServerVersion,
			d.Instructions, d.Capabilities, toolsJSON, rejJSON, hash, mode, basis, res.duration.Milliseconds())
		if err != nil {
			return err
		}
		if hash == prevHash {
			return nil
		}
		added, removed, changed := diffTools(prev, tools)
		_, err = s.diary.AppendTx(ctx, tx, diary.Event{EventType: EventToolsChanged, Actor: actor, Data: map[string]any{
			"integration": st.System, "connection": key, "integration_id": st.IntegrationID, "system": System, "transport": Transport, "server": d.ServerName,
			"first_discovery": first || len(prev) == 0, "tool_count": len(tools), "tools_hash": hash,
			"added": added, "removed": removed, "schema_changed": changed, "rejected": len(rejected),
			"permission_mode": mode,
		}})
		return err
	})
}

func toolHash(t mcpclient.Tool) string {
	b, _ := json.Marshal(t)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

func setHash(tools []storedTool) string {
	h := sha256.New()
	for _, t := range tools {
		h.Write([]byte(t.Name + "=" + t.Hash + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

func diffTools(prev, cur []storedTool) (added, removed, changed []string) {
	old := map[string]string{}
	for _, t := range prev {
		old[t.Name] = t.Hash
	}
	now := map[string]bool{}
	for _, t := range cur {
		now[t.Name] = true
		switch h, ok := old[t.Name]; {
		case !ok:
			added = append(added, t.Name)
		case h != t.Hash:
			changed = append(changed, t.Name)
		}
	}
	for _, t := range prev {
		if !now[t.Name] {
			removed = append(removed, t.Name)
		}
	}
	return nonNil(added), nonNil(removed), nonNil(changed)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// forget drops what Fortik learned from an MCP connection's server once the
// connection is deleted (OnDelete hook). Its credential was deleted from the
// secret store by the integration store; the shared session is closed.
func (s *Service) forget(ctx context.Context, key, actor string) {
	system, err := integrations.ParseKey(key)
	if err != nil || !isMCPSystem(system) {
		return
	}
	s.up(key).drop()
	s.http.CloseIdleConnections()
	s.callHTTP.CloseIdleConnections()
	_, appID, _ := integrations.LogicalID(key)
	note := "token deleted from Fortik's secret store; it is not revoked in QuickStart"
	if system != integrations.SystemNetSuiteQuickStart {
		note = "credentials and OAuth tokens deleted from Fortik's secret store (revocation upstream: see mcp.oauth.revoked)"
	}
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM mcp_connections WHERE integration_key = $1`, key)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		_, err = s.diary.AppendTx(ctx, tx, diary.Event{EventType: EventForgotten, Actor: actor, Data: map[string]any{
			"integration": system, "connection": key, "integration_id": appID, "system": providerOf(system), "transport": Transport, "note": note,
		}})
		return err
	})
	if err != nil {
		s.log.Error("netsuite mcp: forget connection state", "key", key, "err", err)
	}
}

func actorOf(ctx context.Context) string {
	if p, ok := authz.From(ctx); ok {
		return p.Actor()
	}
	return "system:netsuite_quickstart"
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
