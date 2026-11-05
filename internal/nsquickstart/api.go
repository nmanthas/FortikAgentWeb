package nsquickstart

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"fortik/internal/authz"
	"fortik/internal/coverage"
	"fortik/internal/httpx"
	"fortik/internal/integrations"
	"fortik/internal/mcpclient"
)

// View is GET /v1/integrations/{key}/mcp (and the legacy
// /v1/saas/netsuite_quickstart). It never contains a credential.
type View struct {
	Integration   string     `json:"integration"`    // the connection type: netsuite_quickstart | netsuite_mcp
	Key           string     `json:"key"`            // the connection
	IntegrationID string     `json:"integration_id"` // the logical integration (tenant)
	System        string     `json:"system"`
	Transport     string     `json:"transport"`
	Configured    bool       `json:"configured"`
	OAuth         *OAuthView `json:"oauth,omitempty"` // netsuite_mcp only

	State      string `json:"state"`
	StateLabel string `json:"state_label"`
	Detail     string `json:"detail,omitempty"`
	// LastCheckedState is the state of the last check when the settings
	// changed since (State is then saved_not_tested).
	LastCheckedState string `json:"last_checked_state,omitempty"`
	HTTPStatus       *int   `json:"http_status,omitempty"`

	Name        string `json:"name,omitempty"`
	TenantLabel string `json:"tenant_label,omitempty"`
	Endpoint    string `json:"endpoint,omitempty"`
	TransportT  string `json:"transport_type,omitempty"`
	AuthType    string `json:"auth_type,omitempty"`

	EndpointPermitted bool   `json:"endpoint_permitted"`
	EndpointRefusal   string `json:"endpoint_refusal,omitempty"`

	Token TokenView `json:"token"`

	Server       *ServerView       `json:"server,omitempty"`
	Tools        []ToolView        `json:"tools"`
	Rejected     []json.RawMessage `json:"rejected_tools"`
	ToolCount    int               `json:"tool_count"`
	ToolsHash    string            `json:"tools_hash,omitempty"`
	ToolsCurrent bool              `json:"tools_from_current_settings"`
	MappedTools  int               `json:"mapped_tools"`

	PermissionMode  string `json:"permission_mode"`
	PermissionBasis string `json:"permission_basis,omitempty"`

	LastAttemptAt   *time.Time `json:"last_attempt_at,omitempty"`
	LastSuccessAt   *time.Time `json:"last_success_at,omitempty"`
	LastToolsSyncAt *time.Time `json:"last_tools_sync_at,omitempty"`
	DurationMS      int        `json:"duration_ms,omitempty"`

	AgentEndpoint string        `json:"agent_endpoint,omitempty"`
	Activity      *ActivityView `json:"activity,omitempty"`
	KnownGaps     []string      `json:"known_gaps"`

	Enforcement        EnforcementView      `json:"enforcement"`
	Coverage           coverage.Declaration `json:"coverage"`
	RevokeInstructions string               `json:"revoke_instructions"`
}

type TokenView struct {
	Set       bool   `json:"set"`
	ExpiresOn string `json:"expires_on,omitempty"` // as entered by the administrator
	DaysLeft  *int   `json:"days_left,omitempty"`
	Warning   string `json:"warning,omitempty"`
}

type ServerView struct {
	Name            string          `json:"name"`
	Version         string          `json:"version"`
	ProtocolVersion string          `json:"protocol_version"`
	Instructions    string          `json:"instructions,omitempty"` // server-supplied text: display only
	Capabilities    json.RawMessage `json:"capabilities"`
}

type ToolView struct {
	mcpclient.Tool
	DocumentedAccess string `json:"documented_access"`
	// Mapped: the tool is in Fortik's tool mapping for this server type.
	// An unmapped tool is refused (POL-002) and not offered to agents.
	Mapped bool `json:"mapped"`
}

// EnforcementView states what Fortik does with agents' calls to this server.
type EnforcementView struct {
	AgentCallsRouted bool   `json:"agent_calls_routed"`
	PreExecution     string `json:"pre_execution"`
	PostExecution    string `json:"post_execution"`
	Note             string `json:"note"`
}

var enforcementNow = EnforcementView{
	AgentCallsRouted: true,
	PreExecution:     "enforced",
	PostExecution:    coverage.Unsupported,
	Note: "Agents that use Fortik's QuickStart endpoint (" + ProxyPath + " on the gateway, with their Fortik agent token) are decided before " +
		"each tool call reaches QuickStart: reads run under the access profile; writes are held for approval (config netsuite.mcp_writes_require_approval); refusals never reach QuickStart. " +
		"An AI client configured with its own QuickStart token or OAuth grant bypasses Fortik, and QuickStart exposes no change history to " +
		"detect such changes afterwards.",
}

var enforcementAIConnector = EnforcementView{
	AgentCallsRouted: true,
	PreExecution:     "enforced",
	PostExecution:    coverage.Unsupported,
	Note: "Agents that use Fortik's endpoint for this tenant (" + TenantProxyPrefix + "<tenant> on the gateway, with their Fortik agent token) " +
		"are decided before each tool call reaches NetSuite. No AI Connector tool is mapped yet, so every call is refused before it reaches " +
		"NetSuite. An AI client that a NetSuite user authorized directly bypasses Fortik.",
}

// KnownGaps are the enforcement limits of this integration, as verified.
var KnownGaps = []string{
	"Only agents that connect to Fortik's endpoint are governed; a client holding its own QuickStart token or OAuth grant is not seen.",
	"No change history: QuickStart's MCP tools expose no system notes or last-modified times (live get_record_model, 2026-10-25), so changes made outside Fortik are not detected.",
	"Undo exists only for update_record of plain body fields (read before, written back after; last writer wins). Creates, deletes, transforms, record actions, emails, attachments and preferences are not undoable and are held instead.",
	"Deletes and attachment deletes are red: an approval never runs them; a person must do them in QuickStart.",
	"The token acts with its QuickStart user's permissions; Fortik narrows what agents may do but cannot widen or verify QuickStart's own role checks.",
	"Disconnecting does not revoke the token in QuickStart.",
}

// ActivityView summarises the last day of agents' QuickStart calls.
type ActivityView struct {
	WindowHours       int              `json:"window_hours"`
	Allowed           int              `json:"allowed"`
	Held              int              `json:"held"`
	Denied            int              `json:"denied"`
	Executed          int              `json:"executed"`
	Failed            int              `json:"failed"`
	PendingApprovals  int              `json:"pending_approvals"`
	ActiveSuspensions int              `json:"active_netsuite_suspensions"`
	UndoAvailable     int              `json:"undo_available"`
	Recent            []RecentDecision `json:"recent"`
}

// RecentDecision is one decided QuickStart call.
type RecentDecision struct {
	ActionID string    `json:"action_id"`
	AgentID  string    `json:"agent_id"`
	Tool     string    `json:"tool"`
	Decision string    `json:"decision"`
	RuleID   string    `json:"rule_id"`
	Reason   string    `json:"reason"`
	TS       time.Time `json:"ts"`
	Outcome  string    `json:"outcome,omitempty"` // executed | failed | not_executed (only for allowed calls)
	Undo     string    `json:"undo,omitempty"`    // undo handle status, when one exists
}

// connActions selects the actions of one MCP connection ($1 key, $2 legacy:
// the legacy QuickStart connection also owns actions recorded before
// connections were named in targets).
const connActions = `target ->> 'transport' = 'mcp' AND (target ->> 'connection' = $1
	OR ($2 AND system = 'netsuite' AND target ->> 'connection' IS NULL AND target ->> 'integration' = 'netsuite_quickstart'))`

func (s *Service) activity(ctx context.Context, key string) (*ActivityView, error) {
	legacy := key == IntegrationKey
	a := &ActivityView{WindowHours: 24, Recent: []RecentDecision{}}
	rows, err := s.pool.Query(ctx, `SELECT decision, count(*) FROM actions WHERE `+connActions+` AND ts > now() - interval '24 hours' GROUP BY decision`, key, legacy)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var d string
		var n int
		if err := rows.Scan(&d, &n); err != nil {
			rows.Close()
			return nil, err
		}
		switch d {
		case "allow", "allow_reduced":
			a.Allowed += n
		case "hold":
			a.Held += n
		case "deny":
			a.Denied += n
		}
	}
	rows.Close()
	if err := s.pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE event_type = $3), count(*) FILTER (WHERE event_type = $4)
		FROM diary WHERE event_type IN ($3, $4) AND ts > now() - interval '24 hours'
		AND (body_json::jsonb -> 'data' ->> 'connection' = $1 OR ($2 AND body_json::jsonb -> 'data' ->> 'connection' IS NULL))`,
		key, legacy, EventToolExecuted, EventToolFailed).Scan(&a.Executed, &a.Failed); err != nil {
		return nil, err
	}
	if err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM held_actions h JOIN actions a USING (action_id)
		WHERE h.outcome = 'pending' AND h.expires_at > now() AND a.action_id IN (SELECT action_id FROM actions WHERE `+connActions+`)`,
		key, legacy).Scan(&a.PendingApprovals); err != nil {
		return nil, err
	}
	if err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM access_overrides WHERE system = $1 AND status IN ('active', 'blocked')
		AND (expires_at IS NULL OR expires_at > now())`, providerOf(keySystem(key))).Scan(&a.ActiveSuspensions); err != nil {
		return nil, err
	}
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM undo_handles WHERE kind = $1 AND status = 'active' AND expires_at > now()
		AND (handle_json ->> 'key' = $2 OR ($3 AND handle_json ->> 'key' IS NULL))`, KindRecord, key, legacy).Scan(&a.UndoAvailable); err != nil {
		return nil, err
	}
	rows, err = s.pool.Query(ctx, `
		SELECT a.action_id, a.agent_id, COALESCE(a.target ->> 'tool', ''), a.decision, a.rule_id, a.reason, a.ts,
			COALESCE((SELECT CASE WHEN d.event_type = $3 THEN 'executed' ELSE COALESCE(d.body_json::jsonb -> 'data' ->> 'outcome', 'failed') END
				FROM diary d WHERE (d.body_json::jsonb -> 'data' ->> 'action_id') = a.action_id AND d.event_type IN ($3, $4)
				ORDER BY d.seq DESC LIMIT 1), ''),
			COALESCE((SELECT u.status FROM undo_handles u WHERE u.action_id = a.action_id), '')
		FROM actions a WHERE a.`+connActions+` AND a.ts > now() - interval '24 hours'
		ORDER BY a.ts DESC LIMIT 15`, key, legacy, EventToolExecuted, EventToolFailed)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r RecentDecision
		if err := rows.Scan(&r.ActionID, &r.AgentID, &r.Tool, &r.Decision, &r.RuleID, &r.Reason, &r.TS, &r.Outcome, &r.Undo); err != nil {
			return nil, err
		}
		r.Reason = clip(r.Reason, 240)
		a.Recent = append(a.Recent, r)
	}
	return a, rows.Err()
}

// SetAgentEndpoint records the URL agents use (shown in the console).
func (s *Service) SetAgentEndpoint(url string) { s.agentEndpoint = url }

// SetMappings gives the status view the tool mappings (which tools agents
// can use).
func (s *Service) SetMappings(m map[string]*Mapping) { s.mappings = m }

// Status builds one MCP connection's view from its row and last check.
func (s *Service) Status(ctx context.Context, key string) (View, error) {
	system, err := integrations.ParseKey(key)
	if err != nil {
		return View{}, err
	}
	_, appID, _ := integrations.LogicalID(key)
	v := View{
		Integration: system, Key: key, IntegrationID: appID, System: providerOf(system), Transport: Transport,
		State: StateNotConfigured, Tools: []ToolView{}, Rejected: []json.RawMessage{},
		PermissionMode: ModeUnknown, Enforcement: enforcementNow, Coverage: Declaration(), RevokeInstructions: RevokeInstructions,
		AgentEndpoint: s.agentEndpointFor(appID), KnownGaps: KnownGaps,
	}
	switch system {
	case integrations.SystemNetSuiteMCP:
		v.Coverage, v.RevokeInstructions, v.KnownGaps = DeclarationAIConnector(), RevokeInstructionsOAuth, KnownGapsAIConnector
		v.Enforcement = enforcementAIConnector
	case integrations.SystemSalesforceMCP, integrations.SystemServiceNowMCP, integrations.SystemSAPMCP:
		v.Coverage, v.KnownGaps, v.Enforcement = DeclarationSaaSMCP(system), KnownGapsSaaSMCP(system), enforcementSaaSMCP(system)
		v.RevokeInstructions = "Disconnecting deletes the credentials and tokens from Fortik. With the OAuth authorization code flow and a revocation URL, Fortik also asks the provider to revoke its grant and reports whether it confirmed it; a client-credentials client or a bearer token stays valid upstream until you disable or revoke it there."
	}
	if act, err := s.activity(ctx, key); err == nil {
		v.Activity = act
	} else {
		s.log.Warn("netsuite mcp: activity summary", "key", key, "err", err)
	}
	in, err := s.store.GetIntegration(ctx, key)
	if errors.Is(err, integrations.ErrNotConfigured) {
		v.StateLabel = stateLabels[v.State]
		return v, nil
	}
	if err != nil {
		return v, err
	}
	v.Configured = true
	if in.IntegrationID != "" {
		v.IntegrationID = in.IntegrationID
	}
	var cfg map[string]any
	_ = json.Unmarshal(in.Config, &cfg)
	st, _ := settingsFrom(integrations.Resolved{Integration: in, ConfigMap: cfg, Secrets: map[string]string{"personal_access_token": "-"}})
	v.Name, v.TenantLabel, v.Endpoint, v.AuthType = st.Name, st.TenantLabel, st.Endpoint, st.Auth
	v.TransportT = "streamable_http"
	v.EndpointRefusal = s.endpointRefused(ctx, v.Endpoint, system)
	v.EndpointPermitted = v.EndpointRefusal == ""
	switch st.Auth {
	case AuthOAuth:
		v.OAuth = s.oauthView(ctx, st)
		v.Token = TokenView{Set: v.OAuth != nil && v.OAuth.Authorized}
	case AuthBearer:
		v.Token = TokenView{Set: slices.Contains(in.SecretFields, "access_token")}
	case AuthClientCreds:
		v.Token = TokenView{Set: slices.Contains(in.SecretFields, "client_secret")}
	default:
		v.Token = tokenView(slices.Contains(in.SecretFields, "personal_access_token"), st.TokenExpiresOn, time.Now())
	}

	var (
		version                                                         time.Time
		state, detail, proto, sname, sversion, instr, hash, mode, basis string
		httpStatus                                                      *int
		caps, toolsRaw, rejRaw                                          []byte
		attempt                                                         time.Time
		success, synced                                                 *time.Time
		dur                                                             int
	)
	err = s.pool.QueryRow(ctx, `
		SELECT config_version, state, detail, http_status, protocol_version, server_name, server_version, server_instructions,
			capabilities, tools, rejected_tools, tools_hash, permission_mode, permission_basis, duration_ms,
			last_attempt_at, last_success_at, last_tools_sync_at
		FROM mcp_connections WHERE integration_key = $1`, key).Scan(
		&version, &state, &detail, &httpStatus, &proto, &sname, &sversion, &instr, &caps, &toolsRaw, &rejRaw, &hash, &mode, &basis, &dur,
		&attempt, &success, &synced)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		v.State = StateSavedNotTested
		if v.OAuth != nil && !v.OAuth.Authorized {
			v.State, v.Detail = StateAuthRequired, errNotAuthorized.Error()
		}
		v.StateLabel = stateLabels[v.State]
		return v, nil
	case err != nil:
		return v, err
	}
	current := version.Equal(in.UpdatedAt)
	v.State, v.Detail, v.HTTPStatus = state, detail, httpStatus
	if !current {
		v.State, v.LastCheckedState = StateSavedNotTested, state
		v.Detail = "the settings or the token changed since the last check (" + stateLabels[state] + "); run Test connection"
	}
	v.StateLabel = stateLabels[v.State]
	v.LastAttemptAt, v.LastSuccessAt, v.LastToolsSyncAt, v.DurationMS = &attempt, success, synced, dur
	if success != nil {
		v.Server = &ServerView{Name: sname, Version: sversion, ProtocolVersion: proto, Instructions: instr, Capabilities: caps}
		var tools []storedTool
		_ = json.Unmarshal(toolsRaw, &tools)
		m := s.mappings[system]
		for _, t := range tools {
			mapped := false
			if m != nil {
				_, mapped = m.Tools[t.Name]
			}
			if mapped {
				v.MappedTools++
			}
			v.Tools = append(v.Tools, ToolView{Tool: t.Tool, DocumentedAccess: t.DocumentedAccess, Mapped: mapped})
		}
		_ = json.Unmarshal(rejRaw, &v.Rejected)
		v.ToolCount, v.ToolsHash, v.PermissionMode, v.PermissionBasis = len(v.Tools), hash, mode, basis
		// Tools are current only if the last check of these settings succeeded.
		v.ToolsCurrent = current && (state == StateConnected || state == StateConnectedLimit)
		if !v.ToolsCurrent {
			v.PermissionBasis = "from the last successful check (" + synced.UTC().Format(time.RFC3339) + "), not the current settings or token: " + basis
		}
	}
	return v, nil
}

// agentEndpointFor is the URL an agent uses for one tenant's MCP connection.
func (s *Service) agentEndpointFor(integrationID string) string {
	if s.agentEndpoint == "" {
		return ""
	}
	if integrationID == "netsuite:quickstart" || integrationID == "" {
		return s.agentEndpoint
	}
	provider, name, _ := strings.Cut(integrationID, ":")
	return strings.TrimSuffix(s.agentEndpoint, ProxyPath) + "/mcp/" + provider + "/" + name
}

// defaultKey is the connection the legacy single-connection routes mean:
// the legacy QuickStart key, else the only NetSuite MCP connection.
func (s *Service) defaultKey(ctx context.Context) string {
	if _, err := s.store.GetIntegration(ctx, IntegrationKey); err == nil {
		return IntegrationKey
	}
	var keys []string
	for _, k := range s.mcpKeys(ctx) {
		if providerOf(keySystem(k)) == System {
			keys = append(keys, k) // the legacy routes are NetSuite's
		}
	}
	if len(keys) == 1 {
		return keys[0]
	}
	return IntegrationKey
}

// mcpKeys lists every MCP connection.
func (s *Service) mcpKeys(ctx context.Context) []string {
	var keys []string
	for _, sys := range MCPSystems {
		list, err := s.store.List(ctx, sys)
		if err != nil {
			continue
		}
		for _, r := range list {
			keys = append(keys, r.Key)
		}
	}
	return keys
}

func tokenView(set bool, expires string, now time.Time) TokenView {
	t := TokenView{Set: set, ExpiresOn: expires}
	if expires == "" {
		if set {
			t.Warning = "expiration date not entered; QuickStart tokens expire (30 days by default). Enter it to be warned in time."
		}
		return t
	}
	day, err := time.Parse("2006-01-02", expires)
	if err != nil {
		return t
	}
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	left := int(day.Sub(today).Hours() / 24)
	t.DaysLeft = &left
	switch {
	case left < 0:
		t.Warning = "the expiration date entered has passed: QuickStart will reject this token. Create a new token and rotate it here."
	case left <= 7:
		t.Warning = "the token expires soon: create a new token in QuickStart and rotate it here before it stops working."
	}
	return t
}

// Register mounts:
//
//	GET  /v1/integrations/{key}/mcp            auditor or security: connection state, tools, activity, coverage
//	POST /v1/integrations/{key}/mcp/refresh    security: live check and tool rediscovery now
//	GET  /v1/saas/netsuite_quickstart          (legacy) the same for the default QuickStart connection
//	POST /v1/saas/netsuite_quickstart/refresh  (legacy)
//	POST /v1/integrations/{key}/oauth/start    security: begin a NetSuite user's authorization (netsuite_mcp)
//	GET  /v1/oauth/netsuite/callback           the authorization's return
//
// Save, rotate and disconnect use /v1/integrations/{key}.
func (s *Service) Register(mux *http.ServeMux) {
	status := func(w http.ResponseWriter, r *http.Request, key string) {
		if _, ok := authz.Require(w, r, authz.RoleAuditor, authz.RoleSecurity); !ok {
			return
		}
		if sys, err := integrations.ParseKey(key); err != nil || !isMCPSystem(sys) {
			httpx.WriteError(w, http.StatusBadRequest, "not an MCP connection")
			return
		}
		v, err := s.Status(r.Context(), key)
		if err != nil {
			s.log.Error("netsuite mcp status", "err", err)
			httpx.WriteError(w, http.StatusInternalServerError, "status failed (see server log)")
			return
		}
		httpx.WriteJSON(w, http.StatusOK, v)
	}
	refresh := func(w http.ResponseWriter, r *http.Request, key string) {
		p, ok := authz.Require(w, r, authz.RoleSecurity)
		if !ok {
			return
		}
		if sys, err := integrations.ParseKey(key); err != nil || !isMCPSystem(sys) {
			httpx.WriteError(w, http.StatusBadRequest, "not an MCP connection")
			return
		}
		select {
		case s.running <- struct{}{}:
			defer func() { <-s.running }()
		default:
			httpx.WriteError(w, http.StatusConflict, "a connection check is already running")
			return
		}
		ctx := context.WithoutCancel(r.Context()) // the outcome is recorded even if the client leaves
		row, err := s.store.GetIntegration(ctx, key)
		if errors.Is(err, integrations.ErrNotConfigured) {
			httpx.WriteError(w, http.StatusNotFound, key+" is not configured")
			return
		}
		if err != nil {
			s.log.Error("netsuite mcp refresh", "err", err)
			httpx.WriteError(w, http.StatusInternalServerError, "refresh failed (see server log)")
			return
		}
		start := time.Now()
		res := integrations.TestResult{OK: true}
		resolved, err := s.store.Resolve(ctx, key)
		if err == nil {
			row = resolved.Integration
			err = s.check(ctx, resolved, p.Actor())
		}
		if err != nil {
			res = integrations.TestResult{Error: integrations.Sanitize(err.Error(), resolved.Secrets)}
		}
		res.Duration = time.Since(start)
		if _, rerr := s.store.RecordTest(ctx, key, row.UpdatedAt, res, p.Actor()); rerr != nil && !errors.Is(rerr, integrations.ErrChanged) {
			s.log.Error("netsuite mcp: record test", "err", rerr)
		}
		v, verr := s.Status(ctx, key)
		if verr != nil {
			s.log.Error("netsuite mcp status", "err", verr)
			httpx.WriteError(w, http.StatusInternalServerError, "status failed (see server log)")
			return
		}
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": res.OK, "error": res.Error, "duration_ms": res.Duration.Milliseconds(), "status": v})
	}
	mux.HandleFunc("GET /v1/integrations/{key}/mcp", func(w http.ResponseWriter, r *http.Request) { status(w, r, r.PathValue("key")) })
	mux.HandleFunc("POST /v1/integrations/{key}/mcp/refresh", func(w http.ResponseWriter, r *http.Request) { refresh(w, r, r.PathValue("key")) })
	mux.HandleFunc("GET /v1/saas/netsuite_quickstart", func(w http.ResponseWriter, r *http.Request) { status(w, r, s.defaultKey(r.Context())) })
	mux.HandleFunc("POST /v1/saas/netsuite_quickstart/refresh", func(w http.ResponseWriter, r *http.Request) { refresh(w, r, s.defaultKey(r.Context())) })
	s.registerOAuth(mux)
}

// Declaration is the QuickStart integration's coverage after Milestones 1-4
// (2026-10-25). verified_live items are exercised against the real QuickStart
// tenant by scripts/verify-quickstart-live.sh (reads, holds and refusals
// only: no write was executed on the tenant); verified_test items by the
// internal/nsquickstart tests against a LOCAL FAKE MCP server.
func Declaration() coverage.Declaration {
	live := "scripts/verify-quickstart-live.sh against the real QuickStart tenant (2026-10-25)"
	fake := "internal/nsquickstart tests against a LOCAL FAKE MCP server"
	cap := func(dim, status, ev, gap, fix string) coverage.Capability {
		return coverage.Capability{Dimension: dim, Status: status, Evidence: ev, Gap: gap, Fix: fix}
	}
	return coverage.Declaration{
		System: IntegrationKey, Title: "NetSuite QuickStart MCP server", Integrations: []string{IntegrationKey, IntegrationKey + ":*"},
		Interception: "agents call QuickStart through Fortik's MCP endpoint (" + ProxyPath + " on the gateway) with their Fortik token; every tools/call is decided as system netsuite before Fortik forwards it with the QuickStart token it holds",
		Bypass:       "an AI client configured with its own QuickStart token or OAuth grant talks to QuickStart directly; Fortik does not see those calls and QuickStart exposes no history to detect them",
		Capabilities: []coverage.Capability{
			cap(coverage.DimDiscovery, coverage.Unsupported, "", "the QuickStart MCP tools do not list AI clients or tokens; OAuth client registrations are visible only in QuickStart settings", "review QuickStart settings > OAuth client registrations and Personal access tokens"),
			cap(coverage.DimIdentity, coverage.VerifiedLive, live+" (each call carries the agent's Fortik token; the QuickStart token never reaches the agent)", "QuickStart sees one user (the token's) for every agent", ""),
			cap(coverage.DimActivity, coverage.VerifiedLive, live+" (every call is an action; executions are mcp.tool.executed in the Diary)", "only calls made through Fortik", ""),
			cap(coverage.DimDelegation, coverage.VerifiedTest, fake+" (TestProxyDelegatedQuickStartWriteRefused: a read-only agent's task delegated to a read-write agent cannot write through QuickStart, with the X-Fortik-Delegation token or inferred from the open hop; a forged token is refused)", "not exercised on the real tenant", ""),
			cap(coverage.DimPreExec, coverage.VerifiedLive, live+" (reads allowed under the profile; update and delete held; unknown tool, schema violation and read-only profile refused, none reaching QuickStart)", "only calls made through Fortik", ""),
			cap(coverage.DimRevocation, coverage.VerifiedTest, fake+" (killing an agent or revoking its Fortik token stops its calls: it never holds a QuickStart credential)", "the QuickStart token itself has no documented revocation API", "revoke the token in QuickStart settings > Personal access tokens"),
			cap(coverage.DimSuspension, coverage.VerifiedLive, live+" (a timed netsuite suspension refuses the agent's QuickStart calls; other agents unaffected)", "", ""),
			cap(coverage.DimUndo, coverage.VerifiedTest, fake+" (update_record of plain body fields: read before, written back; last writer wins)", "not exercised on the real tenant (needs an approved write); creates, deletes, transforms, actions, emails, attachments and preferences are not undoable", "approve one update of a test record and undo it (docs/QUICKSTART_TESTING.md)"),
			cap(coverage.DimEvidence, coverage.VerifiedLive, live+" (Diary chain verifies)", "", ""),
		},
	}
}

// KnownGapsAIConnector are the limits of a full account's AI Connector
// Service connection, as built (2026-10-27).
var KnownGapsAIConnector = []string{
	"Not verified against a real NetSuite account: the OAuth flow, the token refresh and the MCP calls were exercised only against a local fake.",
	"Fortik has no tool mapping for the AI Connector Service's tools yet (their names and arguments depend on the SuiteApps installed): every tool is refused (POL-002) and none is offered to agents until it is mapped in policies/fortik/netsuite_mcp/data.json.",
	"Every tool runs with the authorizing NetSuite user's role; Fortik cannot read or narrow that role.",
	"The OAuth scope value is not documented by Oracle (configurable; third-party guides use mcp).",
	"Only agents that connect to Fortik's endpoint are governed; a client with its own NetSuite authorization is not seen.",
}

// DeclarationAIConnector is the coverage of a full NetSuite account's AI
// Connector Service connection (netsuite_mcp), as of 2026-10-27: built and
// tested against a local fake only.
func DeclarationAIConnector() coverage.Declaration {
	fake := "internal/nsquickstart tests against a LOCAL FAKE NetSuite OAuth server and MCP server"
	acct := "connect a NetSuite account's AI Connector Service, authorize, Test connection, map its tools"
	cap := func(dim, status, ev, gap, fix string) coverage.Capability {
		return coverage.Capability{Dimension: dim, Status: status, Evidence: ev, Gap: gap, Fix: fix}
	}
	return coverage.Declaration{
		System: integrations.SystemNetSuiteMCP, Title: "NetSuite MCP server (AI Connector Service)", Integrations: []string{integrations.SystemNetSuiteMCP + ":*"},
		Interception: "agents call the account's MCP server through Fortik's endpoint (/mcp/netsuite/<tenant> on the gateway) with their Fortik token; every tools/call is decided as system netsuite before Fortik forwards it with the OAuth access token a NetSuite user granted Fortik",
		Bypass:       "an AI client authorized by a NetSuite user itself (e.g. Claude or ChatGPT connected directly) talks to NetSuite directly",
		Capabilities: []coverage.Capability{
			cap(coverage.DimDiscovery, coverage.Unsupported, "", "the MCP server does not list AI clients; OAuth grants are visible only in NetSuite", "review the integration record's authorizations in NetSuite"),
			cap(coverage.DimIdentity, coverage.VerifiedTest, fake, "not verified on a real account", acct),
			cap(coverage.DimActivity, coverage.VerifiedTest, fake, "only calls made through Fortik", acct),
			cap(coverage.DimDelegation, coverage.VerifiedTest, "the shared NetSuite MCP pipeline (TestProxyDelegatedQuickStartWriteRefused)", "", ""),
			cap(coverage.DimPreExec, coverage.VerifiedTest, fake+" (unmapped tools refused; mapped tools decided)", "no tool mapping exists yet, so every tool is refused", acct),
			cap(coverage.DimRevocation, coverage.VerifiedTest, fake+" (disconnecting calls NetSuite's revoke endpoint and reports what it confirmed)", "not verified on a real account", acct),
			cap(coverage.DimSuspension, coverage.VerifiedTest, fake+" (a timed netsuite suspension refuses the agent's calls on every NetSuite transport)", "", ""),
			cap(coverage.DimUndo, coverage.NotBuilt, "", "the AI Connector Service's tools are not mapped, so no reversal is known", "map the tools first"),
			cap(coverage.DimEvidence, coverage.VerifiedTest, fake+" (Diary)", "", ""),
		},
	}
}

func keySystem(key string) string {
	sys, _ := integrations.ParseKey(key)
	return sys
}

var saasTitle = map[string]string{"salesforce": "Salesforce", "servicenow": "ServiceNow", "sap": "SAP"}

func enforcementSaaSMCP(system string) EnforcementView {
	prov := providerOf(system)
	return EnforcementView{
		AgentCallsRouted: true,
		PreExecution:     "enforced",
		PostExecution:    coverage.Unsupported,
		Note: "Agents that use Fortik's endpoint for this tenant (/mcp/" + prov + "/<tenant> on the gateway, with their Fortik agent token) are decided " +
			"before each tool call reaches the server. No tool of this server is mapped yet, so every call is refused before it reaches " + saasTitle[prov] +
			". A client connected to the server directly bypasses Fortik.",
	}
}

// KnownGapsSaaSMCP are the limits of a Salesforce, ServiceNow or SAP MCP
// connection, as built (2026-10-28).
func KnownGapsSaaSMCP(system string) []string {
	prov := providerOf(system)
	gaps := []string{
		"Not verified against a real " + saasTitle[prov] + " MCP server: the connection check, OAuth and tool calls were exercised only against local fakes.",
		"No tool of this server is mapped (policies/fortik/" + system + "/data.json): every tool is refused (POL-002) and none is offered to agents until it is mapped from the server's tools/list.",
		"Tools run with the identity the server sees (the authorizing user, the OAuth client, or the token's owner); Fortik cannot read or narrow it.",
		"Only agents that connect to Fortik's endpoint are governed; a client connected to the server directly is not seen.",
	}
	switch system {
	case integrations.SystemSalesforceMCP:
		gaps = append(gaps, "Native Agentforce actions do not pass through Fortik and are not blocked before execution.")
	case integrations.SystemSAPMCP:
		gaps = append(gaps, "SAP publishes no native MCP endpoint for S/4HANA that Fortik could verify: this is a server you run or license, named explicitly.")
	}
	return gaps
}

// DeclarationSaaSMCP is the coverage of a Salesforce, ServiceNow or SAP MCP
// connection: built and tested against local fakes only (2026-10-28).
func DeclarationSaaSMCP(system string) coverage.Declaration {
	prov := providerOf(system)
	fake := "internal/nsquickstart tests against a LOCAL FAKE MCP server (and OAuth server)"
	cap := func(dim, status, ev, gap, fix string) coverage.Capability {
		return coverage.Capability{Dimension: dim, Status: status, Evidence: ev, Gap: gap, Fix: fix}
	}
	todo := "connect a real " + saasTitle[prov] + " MCP server, Test connection, map its tools"
	return coverage.Declaration{
		System: system, Title: saasTitle[prov] + " MCP server", Integrations: []string{system, system + ":*"},
		Interception: "agents call the server through Fortik's endpoint (/mcp/" + prov + "/<tenant> on the gateway) with their Fortik token; every tools/call is decided as system " + prov + " before Fortik forwards it with the credential it holds",
		Bypass:       "an AI client connected to the server directly (with its own authorization) talks to " + saasTitle[prov] + " without Fortik",
		Capabilities: []coverage.Capability{
			cap(coverage.DimDiscovery, coverage.Unsupported, "", "the MCP server does not list AI clients", "review the provider's OAuth grants and connected apps"),
			cap(coverage.DimIdentity, coverage.VerifiedTest, fake, "not verified on a real server", todo),
			cap(coverage.DimActivity, coverage.VerifiedTest, fake, "only calls made through Fortik", todo),
			cap(coverage.DimDelegation, coverage.VerifiedTest, "the shared MCP pipeline (delegation checks run in Decide for every system)", "", ""),
			cap(coverage.DimPreExec, coverage.VerifiedTest, fake+" (unmapped tools refused)", "no tool mapping exists yet, so every tool is refused", todo),
			cap(coverage.DimRevocation, coverage.VerifiedTest, fake+" (disconnecting revokes an authorization-code grant when a revocation URL is known)", "client credentials and bearer tokens are not revoked upstream", "disable the client or revoke the token with the provider"),
			cap(coverage.DimSuspension, coverage.VerifiedTest, "policy tests: a timed "+prov+" suspension and the access profile apply to REST and MCP alike", "", ""),
			cap(coverage.DimUndo, coverage.NotBuilt, "", "no tool is mapped, so no reversal is known", "map the tools first"),
			cap(coverage.DimEvidence, coverage.VerifiedTest, fake+" (Diary)", "", ""),
		},
	}
}
