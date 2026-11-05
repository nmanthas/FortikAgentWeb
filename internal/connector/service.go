// Package connector is the SaaS copilot connector broker (Phase 6,
// docs/PHASE6_DESIGN.md §6): "their Workspace, GitHub and Salesforce
// connectors are pointed at Fortik-issued OAuth clients ... their access
// stops when Fortik stops issuing."
//
// A copilot (ChatGPT, Microsoft Copilot, Gemini, Agentforce...) is a Fortik
// agent. Its vendor's connector is configured with Fortik as the OAuth
// server: /oauth/authorize, /oauth/token, a Fortik client id and secret.
// Fortik sends the user to the upstream (Google, GitHub) with ITS OWN OAuth
// client, keeps the upstream refresh token in the secret store, and hands
// the copilot only short-lived upstream access tokens. Every issue and
// refresh is a Fortik decision (system "connector", verb READ for read-only
// scopes, WRITE otherwise): levels,
// timed suspensions and kills apply, and a kill revokes the upstream grant
// so access stops at once.
package connector

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/action"
	"fortik/internal/broker"
	"fortik/internal/control"
	"fortik/internal/decide"
	"fortik/internal/diary"
	"fortik/internal/secrets"
)

// Diary events.
const (
	EventRegistered     = "connector.registered"
	EventDisabled       = "connector.disabled"
	EventAuthorized     = "connector.authorized"
	EventTokenIssued    = "connector.token_issued"
	EventTokenRefused   = "connector.token_refused"
	EventGrantRevoked   = "connector.grant_revoked"
	EventRefreshReuse   = "connector.refresh_reuse"
	EventVendorActivity = "connector.vendor_activity"
)

// System is the Fortik system of connector token decisions.
const System = "connector"

var (
	ErrNotFound      = errors.New("connector not found")
	ErrInvalid       = errors.New("invalid connector request")
	ErrNotConfigured = errors.New("connector upstream not configured")
	ErrConflict      = errors.New("connector conflict")

	vendorPattern = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)
	scopePattern  = regexp.MustCompile(`^[A-Za-z0-9:/._-]{1,200}$`)
)

// Connector is one registered copilot connector (never its secret).
type Connector struct {
	ConnectorID  string    `json:"connector_id"`
	AgentID      string    `json:"agent_id"`
	Vendor       string    `json:"vendor"`
	Upstream     string    `json:"upstream"`
	ClientID     string    `json:"client_id"`
	RedirectURIs []string  `json:"redirect_uris"`
	Scopes       []string  `json:"scopes"`
	Status       string    `json:"status"`
	CreatedBy    string    `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
	ActiveGrants int       `json:"active_grants"`
	Disabled     string    `json:"disabled_reason,omitempty"`
}

// Service is the connector broker.
type Service struct {
	pool    *pgxpool.Pool
	diary   *diary.Diary
	dec     decide.Decider
	ctl     *control.Store
	secrets secrets.Store
	ups     map[string]*Upstream
	public  string
	log     *slog.Logger
	Now     func() time.Time
}

// New builds the broker. ups maps an upstream name to Fortik's client there
// (a missing upstream refuses registration and authorization for it).
func New(pool *pgxpool.Pool, d *diary.Diary, dec decide.Decider, ctl *control.Store, st secrets.Store, ups map[string]*Upstream,
	publicURL string, log *slog.Logger) (*Service, error) {
	if pool == nil || d == nil || dec == nil || ctl == nil || st == nil {
		return nil, errors.New("connector: pool, diary, decider, control store and a writable secret store are required")
	}
	pu, err := url.Parse(publicURL)
	if err != nil || pu.Scheme == "" || pu.Host == "" {
		return nil, fmt.Errorf("connector: connectors.public_url must be an absolute URL, got %q", publicURL)
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Service{pool: pool, diary: d, dec: dec, ctl: ctl, secrets: st, ups: ups, public: strings.TrimRight(publicURL, "/"), log: log, Now: time.Now}, nil
}

func (s *Service) now() time.Time { return s.Now().UTC() }

// CallbackURL is the upstream redirect URI Fortik registers at each provider.
func (s *Service) CallbackURL() string { return s.public + "/oauth/callback" }

// --- registration ---------------------------------------------------------------

// RegisterRequest registers a copilot connector (security).
type RegisterRequest struct {
	AgentID      string   `json:"agent_id"`
	Name         string   `json:"name"`
	Sponsor      string   `json:"sponsor"`
	Team         string   `json:"team"`
	Vendor       string   `json:"vendor"`
	Upstream     string   `json:"upstream"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
	Reason       string   `json:"reason"`
}

// Registered is the registration result: the client secret is shown once.
type Registered struct {
	Connector    Connector `json:"connector"`
	ClientSecret string    `json:"client_secret"`
	AuthorizeURL string    `json:"authorize_url"`
	TokenURL     string    `json:"token_url"`
}

// Register creates the connector (and its copilot agent if it does not exist).
func (s *Service) Register(ctx context.Context, req RegisterRequest, actor string) (Registered, error) {
	if !vendorPattern.MatchString(req.Vendor) {
		return Registered{}, fmt.Errorf("%w: vendor must match %s", ErrInvalid, vendorPattern)
	}
	if _, ok := s.ups[req.Upstream]; !ok {
		return Registered{}, fmt.Errorf("%w: %s (configure connectors.%s)", ErrNotConfigured, req.Upstream, upstreamKey(req.Upstream))
	}
	if strings.TrimSpace(req.Reason) == "" || strings.TrimSpace(req.Sponsor) == "" {
		return Registered{}, fmt.Errorf("%w: sponsor and reason are required", ErrInvalid)
	}
	if len(req.RedirectURIs) == 0 || len(req.RedirectURIs) > 10 {
		return Registered{}, fmt.Errorf("%w: 1 to 10 redirect_uris", ErrInvalid)
	}
	for _, r := range req.RedirectURIs {
		if err := validRedirect(r); err != nil {
			return Registered{}, err
		}
	}
	if req.Upstream == UpstreamGoogle && len(req.Scopes) == 0 {
		return Registered{}, fmt.Errorf("%w: Google connectors need scopes (the most the copilot may ever get)", ErrInvalid)
	}
	if len(req.Scopes) > 50 {
		return Registered{}, fmt.Errorf("%w: at most 50 scopes", ErrInvalid)
	}
	for _, sc := range req.Scopes {
		if !scopePattern.MatchString(sc) {
			return Registered{}, fmt.Errorf("%w: malformed scope %q", ErrInvalid, clip(sc, 60))
		}
	}
	if _, err := s.ctl.Register(ctx, control.Agent{AgentID: req.AgentID, Name: req.Name, Type: "copilot", Platform: req.Vendor,
		Sponsor: req.Sponsor, BusinessUnit: req.Team}, actor); err != nil {
		return Registered{}, fmt.Errorf("connector agent: %w", err)
	}
	clientID := "fortik-" + randHex(12)
	secret := "fcs_" + randToken(32)
	c := Connector{ConnectorID: action.NewID("con"), AgentID: req.AgentID, Vendor: req.Vendor, Upstream: req.Upstream, ClientID: clientID,
		RedirectURIs: req.RedirectURIs, Scopes: nonNil(req.Scopes), Status: "active", CreatedBy: actor, CreatedAt: s.now()}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO connectors (connector_id, agent_id, vendor, upstream, client_id, client_secret_sha256,
			redirect_uris, scopes, created_by, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10)`,
			c.ConnectorID, c.AgentID, c.Vendor, c.Upstream, c.ClientID, sha(secret), c.RedirectURIs, c.Scopes, actor, c.CreatedAt); err != nil {
			return err
		}
		_, err := s.diary.AppendTx(ctx, tx, diary.Event{AgentID: c.AgentID, EventType: EventRegistered, Actor: actor, Data: map[string]any{
			"connector_id": c.ConnectorID, "vendor": c.Vendor, "upstream": c.Upstream, "client_id": c.ClientID,
			"redirect_uris": c.RedirectURIs, "scopes": c.Scopes, "reason": clip(req.Reason, 500)}})
		return err
	})
	if err != nil {
		return Registered{}, err
	}
	return Registered{Connector: c, ClientSecret: secret, AuthorizeURL: s.public + "/oauth/authorize", TokenURL: s.public + "/oauth/token"}, nil
}

func upstreamKey(u string) string {
	if u == UpstreamGitHub {
		return "github"
	}
	return "google"
}

func validRedirect(r string) error {
	u, err := url.Parse(r)
	if err != nil || u.Host == "" || u.Fragment != "" || u.User != nil {
		return fmt.Errorf("%w: redirect_uri %q must be an absolute URL without fragment or credentials", ErrInvalid, clip(r, 100))
	}
	local := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"
	if u.Scheme != "https" && !(u.Scheme == "http" && local) {
		return fmt.Errorf("%w: redirect_uri %q must use https", ErrInvalid, clip(r, 100))
	}
	return nil
}

const connCols = `c.connector_id, c.agent_id, c.vendor, c.upstream, c.client_id, c.redirect_uris, c.scopes, c.status, c.created_by, c.created_at,
	COALESCE(c.disabled_reason, ''),
	(SELECT count(*) FROM connector_grants g WHERE g.connector_id = c.connector_id AND g.status = 'active')::int`

func scanConn(r pgx.Row) (Connector, error) {
	var c Connector
	err := r.Scan(&c.ConnectorID, &c.AgentID, &c.Vendor, &c.Upstream, &c.ClientID, &c.RedirectURIs, &c.Scopes, &c.Status, &c.CreatedBy,
		&c.CreatedAt, &c.Disabled, &c.ActiveGrants)
	if errors.Is(err, pgx.ErrNoRows) {
		return Connector{}, ErrNotFound
	}
	return c, err
}

// List returns every connector (newest first).
func (s *Service) List(ctx context.Context) ([]Connector, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+connCols+` FROM connectors c ORDER BY c.created_at DESC LIMIT 500`)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Connector, error) { return scanConn(r) })
	if out == nil {
		out = []Connector{}
	}
	return out, err
}

// Get returns one connector.
func (s *Service) Get(ctx context.Context, id string) (Connector, error) {
	return scanConn(s.pool.QueryRow(ctx, `SELECT `+connCols+` FROM connectors c WHERE c.connector_id = $1`, id))
}

// Disable stops a connector: no more authorizations or tokens, and every
// grant is revoked upstream. It returns what the revocation achieved.
func (s *Service) Disable(ctx context.Context, id, reason, actor string) (map[string]string, error) {
	if strings.TrimSpace(reason) == "" {
		return nil, fmt.Errorf("%w: reason is required", ErrInvalid)
	}
	c, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE connectors SET status = 'disabled', disabled_reason = $2, updated_at = now() WHERE connector_id = $1`,
			id, clip(reason, 500)); err != nil {
			return err
		}
		_, err := s.diary.AppendTx(ctx, tx, diary.Event{AgentID: c.AgentID, EventType: EventDisabled, Actor: actor,
			Data: map[string]any{"connector_id": id, "reason": clip(reason, 500)}})
		return err
	})
	if err != nil {
		return nil, err
	}
	return s.revokeGrants(ctx, `connector_id = $1`, id, "connector disabled: "+reason, actor)
}

// --- OAuth: authorization ---------------------------------------------------------

// OAuthError is an RFC 6749 error. Redirect is set when it must be returned
// to the client's redirect URI (only after the URI was validated).
type OAuthError struct {
	Code     string
	Desc     string
	Status   int
	Redirect string
	State    string
}

func (e *OAuthError) Error() string { return e.Code + ": " + e.Desc }

func oauthErr(code, desc string, status int) *OAuthError {
	return &OAuthError{Code: code, Desc: desc, Status: status}
}

// Authorize validates the client's request and returns the upstream consent
// URL to send the browser to.
func (s *Service) Authorize(ctx context.Context, q url.Values) (string, *OAuthError) {
	c, err := s.byClientID(ctx, q.Get("client_id"))
	if err != nil || c.Status != "active" {
		return "", oauthErr("unauthorized_client", "unknown or disabled client_id", 400)
	}
	redirect := q.Get("redirect_uri")
	if redirect == "" && len(c.RedirectURIs) == 1 {
		redirect = c.RedirectURIs[0]
	}
	if !slices.Contains(c.RedirectURIs, redirect) {
		return "", oauthErr("invalid_request", "redirect_uri is not registered for this client", 400)
	}
	state := q.Get("state")
	fail := func(code, desc string) (string, *OAuthError) {
		return "", &OAuthError{Code: code, Desc: desc, Status: 302, Redirect: redirect, State: state}
	}
	if q.Get("response_type") != "code" {
		return fail("unsupported_response_type", "only response_type=code")
	}
	if len(state) > 512 {
		return fail("invalid_request", "state too long")
	}
	scopes := c.Scopes
	if req := strings.Fields(q.Get("scope")); len(req) > 0 {
		scopes = nil
		for _, sc := range req {
			if slices.Contains(c.Scopes, sc) { // never more than registered
				scopes = append(scopes, sc)
			}
		}
		if len(scopes) == 0 && c.Upstream == UpstreamGoogle {
			return fail("invalid_scope", "none of the requested scopes is allowed for this connector")
		}
	}
	challenge, method := q.Get("code_challenge"), q.Get("code_challenge_method")
	if challenge != "" && method != "S256" {
		return fail("invalid_request", "code_challenge_method must be S256")
	}
	up, ok := s.ups[c.Upstream]
	if !ok {
		return fail("temporarily_unavailable", "upstream not configured")
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM connector_pending WHERE connector_id = $1 AND expires_at <= $2`, c.ConnectorID, s.now()); err != nil {
		s.log.Error("connector: starting an authorization failed", "connector_id", c.ConnectorID, "err", err)
		return fail("server_error", "could not start the authorization")
	}
	var open int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM connector_pending WHERE connector_id = $1`, c.ConnectorID).Scan(&open); err != nil {
		s.log.Error("connector: starting an authorization failed", "connector_id", c.ConnectorID, "err", err)
		return fail("server_error", "could not start the authorization")
	}
	if open >= maxOpenAuthorizations {
		return fail("temporarily_unavailable", "too many authorizations in progress for this client: try again in a few minutes")
	}
	txn := randToken(32)
	if _, err := s.pool.Exec(ctx, `INSERT INTO connector_pending (txn_sha256, connector_id, redirect_uri, client_state, scopes, code_challenge,
		code_challenge_method, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, sha(txn), c.ConnectorID, redirect, state, nonNil(scopes), challenge,
		method, s.now().Add(10*time.Minute)); err != nil {
		s.log.Error("connector: starting an authorization failed", "connector_id", c.ConnectorID, "err", err)
		return fail("server_error", "could not start the authorization")
	}
	return up.AuthorizeURL(txn, s.CallbackURL(), scopes), nil
}

// Callback completes the upstream consent: it keeps the upstream grant and
// returns the client's redirect with a one-time Fortik code.
func (s *Service) Callback(ctx context.Context, q url.Values, actor string) (string, *OAuthError) {
	var c Connector
	var redirect, state, challenge, method string
	var scopes []string
	var expires time.Time
	err := s.pool.QueryRow(ctx, `DELETE FROM connector_pending WHERE txn_sha256 = $1
		RETURNING connector_id, redirect_uri, client_state, scopes, code_challenge, code_challenge_method, expires_at`, sha(q.Get("state"))).
		Scan(&c.ConnectorID, &redirect, &state, &scopes, &challenge, &method, &expires)
	if err != nil || s.now().After(expires) {
		return "", oauthErr("invalid_request", "unknown or expired authorization (start again from the copilot)", 400)
	}
	fail := func(code, desc string) (string, *OAuthError) {
		return "", &OAuthError{Code: code, Desc: desc, Status: 302, Redirect: redirect, State: state}
	}
	if c, err = s.Get(ctx, c.ConnectorID); err != nil || c.Status != "active" {
		return fail("access_denied", "connector disabled")
	}
	if e := q.Get("error"); e != "" {
		return fail("access_denied", "the user or the upstream refused: "+clip(e, 60))
	}
	up, ok := s.ups[c.Upstream]
	if !ok {
		return fail("temporarily_unavailable", "upstream not configured")
	}
	t, err := up.Exchange(ctx, q.Get("code"), s.CallbackURL())
	if err != nil {
		s.log.Warn("connector: upstream code exchange failed", "connector_id", c.ConnectorID, "err", err)
		return fail("access_denied", "the upstream refused the authorization")
	}
	grantID := action.NewID("cgr")
	secretName := "connector_grant_" + strings.ToLower(grantID)
	if err := s.secrets.Put(ctx, secretName, []byte(t.RefreshToken)); err != nil {
		return fail("server_error", "could not store the upstream grant")
	}
	code := randToken(32)
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO connector_grants (grant_id, connector_id, agent_id, scopes, upstream_secret)
			VALUES ($1,$2,$3,$4,$5)`, grantID, c.ConnectorID, c.AgentID, nonNil(scopes), secretName); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM connector_codes WHERE connector_id = $1 AND expires_at < $2`, c.ConnectorID,
			s.now().Add(-codeReplayWindow)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO connector_codes (code_sha256, grant_id, connector_id, redirect_uri, code_challenge,
			code_challenge_method, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`, sha(code), grantID, c.ConnectorID, redirect, challenge, method,
			s.now().Add(2*time.Minute)); err != nil {
			return err
		}
		_, err := s.diary.AppendTx(ctx, tx, diary.Event{AgentID: c.AgentID, EventType: EventAuthorized, Actor: actor, Data: map[string]any{
			"connector_id": c.ConnectorID, "grant_id": grantID, "upstream": c.Upstream, "scopes": nonNil(scopes)}})
		return err
	})
	if err != nil {
		s.log.Error("connector: recording the authorization failed", "connector_id", c.ConnectorID, "err", err)
		_ = s.secrets.Delete(ctx, secretName)
		return fail("server_error", "could not record the authorization")
	}
	u, _ := url.Parse(redirect)
	rq := u.Query()
	rq.Set("code", code)
	if state != "" {
		rq.Set("state", state)
	}
	u.RawQuery = rq.Encode()
	return u.String(), nil
}

// --- OAuth: token endpoint ------------------------------------------------------------

// TokenResponse is the RFC 6749 §5.1 response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope,omitempty"`
}

type grantRow struct {
	id, connectorID, agentID, secret string
	scopes                           []string
}

// Token serves /oauth/token for an authenticated client.
func (s *Service) Token(ctx context.Context, clientID, clientSecret string, form url.Values) (TokenResponse, *OAuthError) {
	c, err := s.byClientID(ctx, clientID)
	if err != nil || !secretMatches(ctx, s.pool, c.ConnectorID, clientSecret) {
		return TokenResponse{}, oauthErr("invalid_client", "client authentication failed", 401)
	}
	if c.Status != "active" {
		return TokenResponse{}, oauthErr("invalid_client", "connector disabled", 401)
	}
	var g grantRow
	switch form.Get("grant_type") {
	case "authorization_code":
		var redirect, challenge, method string
		var expires time.Time
		var used *time.Time
		err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
			if err := tx.QueryRow(ctx, `SELECT k.redirect_uri, k.code_challenge, k.code_challenge_method, k.expires_at, k.used_at,
				g.grant_id, g.connector_id, g.agent_id, g.upstream_secret, g.scopes
				FROM connector_codes k JOIN connector_grants g ON g.grant_id = k.grant_id
				WHERE k.code_sha256 = $1 AND k.connector_id = $2 AND g.status = 'active' FOR UPDATE OF k`, sha(form.Get("code")), c.ConnectorID).
				Scan(&redirect, &challenge, &method, &expires, &used, &g.id, &g.connectorID, &g.agentID, &g.secret, &g.scopes); err != nil {
				return err
			}
			if used != nil {
				return errUsed
			}
			_, err := tx.Exec(ctx, `UPDATE connector_codes SET used_at = now() WHERE code_sha256 = $1`, sha(form.Get("code")))
			return err
		})
		if errors.Is(err, errUsed) {
			// A replayed code: the grant it created may be compromised.
			_, _ = s.revokeGrants(ctx, `grant_id = $1`, g.id, "authorization code replayed", "system:connector")
			return TokenResponse{}, oauthErr("invalid_grant", "authorization code already used: the grant was revoked", 400)
		}
		if err != nil || s.now().After(expires) || !redirectMatches(c, form.Get("redirect_uri"), redirect) {
			return TokenResponse{}, oauthErr("invalid_grant", "unknown, expired or mismatched authorization code", 400)
		}
		if challenge != "" && !pkceOK(challenge, method, form.Get("code_verifier")) {
			return TokenResponse{}, oauthErr("invalid_grant", "PKCE verification failed", 400)
		}
		return s.issue(ctx, c, g, "authorization_code", "")
	case "refresh_token":
		rt := form.Get("refresh_token")
		h := sha(rt)
		err := s.pool.QueryRow(ctx, `SELECT grant_id, connector_id, agent_id, upstream_secret, scopes FROM connector_grants
			WHERE refresh_sha256 = $1 AND connector_id = $2 AND status = 'active'`, h, c.ConnectorID).
			Scan(&g.id, &g.connectorID, &g.agentID, &g.secret, &g.scopes)
		if errors.Is(err, pgx.ErrNoRows) {
			// A rotated-out token presented again means two parties hold it:
			// revoke the grant (RFC 6819 §5.2.2.3).
			var stolen string
			if s.pool.QueryRow(ctx, `SELECT grant_id FROM connector_grants WHERE previous_refresh_sha256 = $1 AND status = 'active'`, h).Scan(&stolen) == nil {
				_, _ = s.revokeGrants(ctx, `grant_id = $1`, stolen, "rotated refresh token reused", "system:connector")
				_, _ = s.diary.Append(ctx, diary.Event{AgentID: c.AgentID, EventType: EventRefreshReuse, Actor: "system:connector",
					Data: map[string]any{"connector_id": c.ConnectorID, "grant_id": stolen}})
			}
			return TokenResponse{}, oauthErr("invalid_grant", "unknown or revoked refresh token", 400)
		}
		if err != nil {
			return TokenResponse{}, oauthErr("server_error", "token lookup failed", 500)
		}
		return s.issue(ctx, c, g, "refresh_token", h)
	}
	return TokenResponse{}, oauthErr("unsupported_grant_type", "authorization_code or refresh_token", 400)
}

var errUsed = errors.New("code used")

// Bounds on the unauthenticated authorize endpoint: a client id is not a
// secret, so open authorizations per connector are capped, and expired rows
// are pruned as new ones arrive. Used codes are kept a day after expiry so a
// late replay still revokes its grant.
const (
	maxOpenAuthorizations = 200
	codeReplayWindow      = 24 * time.Hour
)

// redirectMatches: the token request's redirect_uri must equal the one the
// code was issued for; it may be omitted when the authorize request could
// omit it too (one registered URI), RFC 6749 §4.1.3.
func redirectMatches(c Connector, given, issued string) bool {
	if given == issued {
		return true
	}
	return given == "" && len(c.RedirectURIs) == 1 && c.RedirectURIs[0] == issued
}

// issue decides, refreshes upstream and rotates the Fortik refresh token.
func (s *Service) issue(ctx context.Context, c Connector, g grantRow, grantType, oldHash string) (TokenResponse, *OAuthError) {
	verb := action.VerbRead
	if anyWrite(c.Upstream, g.scopes) {
		verb = action.VerbWrite
	}
	a := action.Action{AgentID: c.AgentID, System: System, Verb: verb, Source: action.SourceConnector,
		Target: map[string]any{"connector_id": c.ConnectorID, "vendor": c.Vendor, "upstream": c.Upstream,
			"upstream_systems": UpstreamSystems[c.Upstream], "scopes": g.scopes, "write": anyWrite(c.Upstream, g.scopes),
			"grant_type": grantType, "grant_id": g.id, "connector_status": c.Status}}
	out, err := s.dec.Decide(ctx, a)
	if err != nil {
		return TokenResponse{}, oauthErr("server_error", "Fortik could not decide", 503)
	}
	if !out.Result.Decision.Executes() || out.FailClosed {
		_, _ = s.diary.Append(ctx, diary.Event{AgentID: c.AgentID, EventType: EventTokenRefused, Actor: "system:connector", Data: map[string]any{
			"connector_id": c.ConnectorID, "grant_id": g.id, "action_id": out.Action.ActionID, "rule_id": out.Result.RuleID,
			"decision": string(out.Result.Decision)}})
		return TokenResponse{}, oauthErr("invalid_grant", fmt.Sprintf("refused by Fortik (%s: %s), action_id=%s", out.Result.RuleID,
			clip(out.Result.Reason, 200), out.Action.ActionID), 400)
	}
	up, ok := s.ups[c.Upstream]
	if !ok {
		return TokenResponse{}, oauthErr("temporarily_unavailable", "upstream not configured", 503)
	}
	refresh, err := s.secrets.Get(ctx, g.secret)
	if err != nil {
		return TokenResponse{}, oauthErr("server_error", "upstream grant unavailable", 503)
	}
	t, err := up.Refresh(ctx, string(refresh))
	if err != nil {
		s.log.Warn("connector: upstream refresh failed", "grant_id", g.id, "err", err)
		return TokenResponse{}, oauthErr("invalid_grant", "the upstream refused to refresh the grant", 400)
	}
	if t.RefreshToken != "" && t.RefreshToken != string(refresh) {
		if err := s.secrets.Put(ctx, g.secret, []byte(t.RefreshToken)); err != nil {
			return TokenResponse{}, oauthErr("server_error", "could not store the rotated upstream grant", 503)
		}
	}
	rt := "frt_" + randToken(32)
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE connector_grants SET refresh_sha256 = $2, previous_refresh_sha256 = refresh_sha256, last_issued_at = now()
			WHERE grant_id = $1 AND status = 'active' AND ($3 = '' OR refresh_sha256 = $3)`, g.id, sha(rt), oldHash)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errUsed // revoked, or a concurrent refresh with the same token won
		}
		_, err = s.diary.AppendTx(ctx, tx, diary.Event{AgentID: c.AgentID, EventType: EventTokenIssued, Actor: "system:connector", Data: map[string]any{
			"connector_id": c.ConnectorID, "grant_id": g.id, "action_id": out.Action.ActionID, "grant_type": grantType,
			"expires_in": t.ExpiresIn, "scopes": g.scopes}})
		return err
	})
	if err != nil {
		return TokenResponse{}, oauthErr("invalid_grant", "the grant changed while the token was being issued", 400)
	}
	return TokenResponse{AccessToken: t.AccessToken, TokenType: "Bearer", ExpiresIn: t.ExpiresIn, RefreshToken: rt,
		Scope: strings.Join(g.scopes, " ")}, nil
}

// RevokeToken serves RFC 7009 /oauth/revoke: the client gives up its grant.
func (s *Service) RevokeToken(ctx context.Context, clientID, clientSecret, token string) *OAuthError {
	c, err := s.byClientID(ctx, clientID)
	if err != nil || !secretMatches(ctx, s.pool, c.ConnectorID, clientSecret) {
		return oauthErr("invalid_client", "client authentication failed", 401)
	}
	var gid string
	if s.pool.QueryRow(ctx, `SELECT grant_id FROM connector_grants WHERE refresh_sha256 = $1 AND connector_id = $2 AND status = 'active'`,
		sha(token), c.ConnectorID).Scan(&gid) == nil {
		_, _ = s.revokeGrants(ctx, `grant_id = $1`, gid, "revoked by the client", "client:"+c.ClientID)
	}
	return nil // RFC 7009: unknown tokens are not an error
}

// --- revocation ------------------------------------------------------------------

// Mint implements broker.Adapter: connector tokens are issued only through
// the OAuth token endpoint, never minted directly.
func (s *Service) Mint(context.Context, string, map[string]any, time.Duration) (broker.Credential, error) {
	return broker.Credential{}, errors.New("connector tokens are issued through /oauth/token only")
}

// System implements broker.Adapter (kill and quarantine revoke connector grants).
func (s *Service) System() string { return System }

// RevokeAgent revokes every active grant of the agent's connectors upstream.
func (s *Service) RevokeAgent(ctx context.Context, agentID string) (string, error) {
	res, err := s.revokeGrants(ctx, `agent_id = $1`, agentID, "agent containment", "system:connector")
	return describe(res), err
}

// RevokeAgentSystem revokes the agent's grants whose upstream reaches system
// (a timed suspension of gmail, drive or github stops copilots at once).
func (s *Service) RevokeAgentSystem(ctx context.Context, agentID, system string) (string, error) {
	var ups []string
	for u, systems := range UpstreamSystems {
		if slices.Contains(systems, system) {
			ups = append(ups, u)
		}
	}
	res, err := s.revokeGrants(ctx, `agent_id = $1 AND connector_id IN (SELECT connector_id FROM connectors WHERE upstream = ANY($2))`,
		agentID, "timed suspension of "+system, "system:connector", ups)
	return describe(res), err
}

func describe(res map[string]string) string {
	if len(res) == 0 {
		return "no active connector grants"
	}
	var parts []string
	for _, k := range slices.Sorted(mapsKeys(res)) {
		parts = append(parts, k+": "+res[k])
	}
	return strings.Join(parts, "; ")
}

// revokeGrants revokes the matching active grants: the upstream grant is
// ended and Fortik refuses every later refresh. An upstream failure is
// reported (the local refusal still holds; access then ends at the current
// access token's expiry).
func (s *Service) revokeGrants(ctx context.Context, where string, arg any, reason, actor string, more ...any) (map[string]string, error) {
	args := append([]any{arg}, more...)
	rows, err := s.pool.Query(ctx, `UPDATE connector_grants SET status = 'revoked', revoked_at = now(), revoke_reason = $`+fmt.Sprint(len(args)+1)+`,
		refresh_sha256 = NULL WHERE status = 'active' AND `+where+` RETURNING grant_id, connector_id, agent_id, upstream_secret`,
		append(args, clip(reason, 300))...)
	if err != nil {
		return nil, err
	}
	type g struct{ id, conn, agent, secret string }
	gs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (g, error) {
		var x g
		return x, r.Scan(&x.id, &x.conn, &x.agent, &x.secret)
	})
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	var errs []error
	for _, x := range gs {
		c, err := s.Get(ctx, x.conn)
		desc := "Fortik refuses refreshes; "
		var upErr error
		if err != nil {
			upErr = err
		} else if up, ok := s.ups[c.Upstream]; !ok {
			upErr = ErrNotConfigured
		} else if refresh, err := s.secrets.Get(ctx, x.secret); err != nil {
			upErr = fmt.Errorf("upstream grant unavailable: %w", err)
		} else if err := up.Revoke(ctx, string(refresh)); err != nil {
			upErr = err
		} else {
			_ = s.secrets.Delete(ctx, x.secret)
		}
		if upErr != nil {
			desc += "upstream revoke FAILED (" + clip(upErr.Error(), 200) + "): access ends when the current access token expires"
			errs = append(errs, fmt.Errorf("grant %s: %w", x.id, upErr))
		} else {
			desc += "upstream grant revoked"
		}
		out[x.id] = desc
		_, _ = s.diary.Append(ctx, diary.Event{AgentID: x.agent, EventType: EventGrantRevoked, Actor: actor, Data: map[string]any{
			"connector_id": x.conn, "grant_id": x.id, "reason": clip(reason, 300), "upstream_revoked": upErr == nil, "result": desc}})
	}
	return out, errors.Join(errs...)
}

// --- helpers --------------------------------------------------------------------

func (s *Service) byClientID(ctx context.Context, clientID string) (Connector, error) {
	if clientID == "" || len(clientID) > 64 {
		return Connector{}, ErrNotFound
	}
	return scanConn(s.pool.QueryRow(ctx, `SELECT `+connCols+` FROM connectors c WHERE c.client_id = $1`, clientID))
}

func secretMatches(ctx context.Context, pool *pgxpool.Pool, connectorID, secret string) bool {
	var want string
	if pool.QueryRow(ctx, `SELECT client_secret_sha256 FROM connectors WHERE connector_id = $1`, connectorID).Scan(&want) != nil {
		return false
	}
	return secret != "" && subtle.ConstantTimeCompare([]byte(sha(secret)), []byte(want)) == 1
}

func pkceOK(challenge, method, verifier string) bool {
	if method != "S256" || len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(challenge)) == 1
}

// anyWrite: a scope that can change data (Google: anything not read-only;
// GitHub user tokens: permissions come from the app, assume write).
func anyWrite(upstream string, scopes []string) bool {
	if upstream == UpstreamGitHub {
		return true
	}
	for _, sc := range scopes {
		if !strings.HasSuffix(sc, ".readonly") && !strings.HasSuffix(sc, ".metadata") && sc != "openid" && sc != "email" && sc != "profile" {
			return true
		}
	}
	return false
}

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("connector: no randomness: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("connector: no randomness: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func mapsKeys(m map[string]string) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}
