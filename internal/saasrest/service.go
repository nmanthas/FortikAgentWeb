// Package saasrest is Fortik's REST transport for Salesforce, ServiceNow and
// SAP: each connection's provider-specific authentication, a read-only live
// check that discovers what the credentials can reach, and the gateway
// adapters that decide every agent call (system salesforce | servicenow |
// sap, transport rest_api) before Fortik forwards it with its own token.
//
// Credentials come from the secret store and are sent only to permitted
// hosts (Guard). They are never logged, stored in Postgres, written to the
// Diary or returned by the API.
package saasrest

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/authz"
	"fortik/internal/httpx"
	"fortik/internal/integrations"
)

// Check states (rest_connections.state). not_configured and
// saved_not_tested are derived.
const (
	StateNotConfigured  = "not_configured"
	StateSavedNotTested = "saved_not_tested"
	StateConnected      = "connected"
	StateAuthFailed     = "auth_failed"
	StatePermission     = "permission_denied"
	StateNotFound       = "not_found"
	StateUnavailable    = "unavailable"
	StateNotPermitted   = "endpoint_not_permitted"
	StateInvalid        = "invalid_settings"
)

var stateLabels = map[string]string{
	StateNotConfigured:  "Not configured",
	StateSavedNotTested: "Configuration saved but not tested",
	StateConnected:      "Connected",
	StateAuthFailed:     "Authentication failed",
	StatePermission:     "Permission denied",
	StateNotFound:       "API or resource not found",
	StateUnavailable:    "Connection test failed",
	StateNotPermitted:   "Endpoint not permitted",
	StateInvalid:        "Settings incomplete",
}

// Systems are the REST connection types this package serves.
var Systems = []string{integrations.SystemSalesforce, integrations.SystemServiceNow, integrations.SystemSAP}

// CheckTimeout bounds one live check (below the integrations handler's).
const CheckTimeout = 12 * time.Second

// Service checks REST connections and holds their tokens.
type Service struct {
	pool  *pgxpool.Pool
	store *integrations.PGStore
	guard Guard
	http  *http.Client
	log   *slog.Logger

	mu     sync.Mutex
	tokens map[string]token // per connection key

	agentBase string // the gateway's public URL, for the status view
}

// New wires the service and registers its cleanup on disconnect.
func New(pool *pgxpool.Pool, store *integrations.PGStore, guard Guard, log *slog.Logger) *Service {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	s := &Service{pool: pool, store: store, guard: guard, http: guard.Client(CheckTimeout), log: log, tokens: map[string]token{}}
	if store != nil {
		store.OnDelete(s.forget)
	}
	return s
}

// SetAgentBase sets the gateway URL agents use (shown in the status).
func (s *Service) SetAgentBase(u string) { s.agentBase = u }

func isREST(system string) bool { return contains(Systems, system) }

// Token returns a valid Authorization header for the connection, from the
// cache or a new token request (the gateway's use).
func (s *Service) Token(ctx context.Context, st Settings) (string, error) {
	s.mu.Lock()
	t, ok := s.tokens[st.Key]
	s.mu.Unlock()
	if ok && t.version.Equal(st.Version) && time.Now().Before(t.expires) {
		return t.header, nil
	}
	t, err := s.authenticate(ctx, st)
	if err != nil {
		return "", err
	}
	t.version = st.Version
	s.mu.Lock()
	s.tokens[st.Key] = t
	s.mu.Unlock()
	return t.header, nil
}

// Drop forgets a connection's cached token (e.g. after a 401 upstream).
func (s *Service) Drop(key string) {
	s.mu.Lock()
	delete(s.tokens, key)
	s.mu.Unlock()
}

type tester struct {
	s      *Service
	system string
}

func (t tester) System() string { return t.system }

// Test implements integrations.Tester (Integrations > Test connection).
func (t tester) Test(ctx context.Context, r integrations.Resolved) error {
	return t.s.check(ctx, r)
}

// Testers are the connection testers of every REST connection type here.
func (s *Service) Testers() []integrations.Tester {
	out := make([]integrations.Tester, 0, len(Systems))
	for _, sys := range Systems {
		out = append(out, tester{s, sys})
	}
	return out
}

// check runs one live, read-only check and records it. The error starts
// with the state label so the integration's last_error explains itself.
func (s *Service) check(ctx context.Context, r integrations.Resolved) error {
	start := time.Now()
	cctx, cancel := ctxWith(ctx, CheckTimeout)
	defer cancel()
	st, err := settingsFrom(r)
	var res probeResult
	switch {
	case err != nil:
		res = probeResult{state: StateInvalid, detail: err.Error()}
	case s.guard.Refused(st.System, st.Base) != "":
		res = probeResult{state: StateNotPermitted, detail: "API URL not permitted: " + s.guard.Refused(st.System, st.Base)}
	default:
		s.Drop(st.Key)
		t, terr := s.authenticate(cctx, st)
		var ae *authError
		switch {
		case errors.As(terr, &ae):
			res = probeResult{state: StateAuthFailed, detail: ae.detail, httpStatus: ae.status}
		case errors.Is(terr, errSettings):
			res = probeResult{state: StateInvalid, detail: terr.Error()}
		case terr != nil:
			res = failure(terr)
		default:
			switch st.System {
			case integrations.SystemSalesforce:
				res = s.probeSalesforce(cctx, st, t)
			case integrations.SystemServiceNow:
				res = s.probeServiceNow(cctx, st, t)
			case integrations.SystemSAP:
				res = s.probeSAP(cctx, st, t)
			}
			if res.state == StateConnected {
				t.version = st.Version
				s.mu.Lock()
				s.tokens[st.Key] = t
				s.mu.Unlock()
			}
		}
	}
	res.detail = integrations.Sanitize(res.detail, r.Secrets)
	if err := s.record(ctx, r, st, res, time.Since(start)); err != nil {
		s.log.Error("saas rest: record check", "key", r.Key, "err", err)
	}
	s.log.Info("saas rest connection checked", "key", r.Key, "state", res.state, "duration_ms", time.Since(start).Milliseconds())
	if res.state == StateConnected {
		return nil
	}
	return errors.New(stateLabels[res.state] + ": " + res.detail)
}

func (s *Service) record(ctx context.Context, r integrations.Resolved, st Settings, res probeResult, d time.Duration) error {
	if s.pool == nil {
		return nil
	}
	ident, _ := json.Marshal(nonNil(res.identity))
	caps, _ := json.Marshal(nonNil(res.capabilities))
	var status *int
	if res.httpStatus != 0 {
		status = &res.httpStatus
	}
	ok := res.state == StateConnected
	_, err := s.pool.Exec(context.WithoutCancel(ctx), `
		INSERT INTO rest_connections (integration_key, config_version, state, detail, http_status, endpoint, identity, capabilities, duration_ms, last_attempt_at, last_success_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now(), CASE WHEN $10 THEN now() END)
		ON CONFLICT (integration_key) DO UPDATE SET config_version = EXCLUDED.config_version, state = EXCLUDED.state, detail = EXCLUDED.detail,
			http_status = EXCLUDED.http_status, endpoint = EXCLUDED.endpoint, identity = EXCLUDED.identity,
			capabilities = CASE WHEN $10 THEN EXCLUDED.capabilities ELSE rest_connections.capabilities END,
			duration_ms = EXCLUDED.duration_ms, last_attempt_at = now(),
			last_success_at = CASE WHEN $10 THEN now() ELSE rest_connections.last_success_at END`,
		r.Key, r.UpdatedAt, res.state, clip(res.detail, 1000), status, st.Base, ident, caps, d.Milliseconds(), ok)
	return err
}

func nonNil(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

// forget drops a disconnected connection's check result and token.
func (s *Service) forget(ctx context.Context, key, _ string) {
	system, err := integrations.ParseKey(key)
	if err != nil || !isREST(system) {
		return
	}
	s.Drop(key)
	if s.pool != nil {
		if _, err := s.pool.Exec(ctx, `DELETE FROM rest_connections WHERE integration_key = $1`, key); err != nil {
			s.log.Error("saas rest: forget", "key", key, "err", err)
		}
	}
}

// View is GET /v1/integrations/{key}/check: the selected REST connection's
// state, from its last live check (never from saved settings alone).
type View struct {
	Key                 string         `json:"key"`
	System              string         `json:"system"`
	IntegrationID       string         `json:"integration_id"`
	Transport           string         `json:"transport"`
	Configured          bool           `json:"configured"`
	State               string         `json:"state"`
	StateLabel          string         `json:"state_label"`
	Detail              string         `json:"detail,omitempty"`
	LastCheckedState    string         `json:"last_checked_state,omitempty"`
	HTTPStatus          *int           `json:"http_status,omitempty"`
	Endpoint            string         `json:"endpoint,omitempty"`
	EndpointPermitted   bool           `json:"endpoint_permitted"`
	EndpointRefusal     string         `json:"endpoint_refusal,omitempty"`
	Auth                string         `json:"auth,omitempty"`
	Identity            map[string]any `json:"identity"`
	Capabilities        map[string]any `json:"capabilities"`
	CapabilitiesCurrent bool           `json:"capabilities_from_current_settings"`
	LastAttemptAt       *time.Time     `json:"last_attempt_at,omitempty"`
	LastSuccessAt       *time.Time     `json:"last_success_at,omitempty"`
	DurationMS          int            `json:"duration_ms"`
	AgentEndpoint       string         `json:"agent_endpoint,omitempty"`
	KnownGaps           []string       `json:"known_gaps"`
}

// Status reports a REST connection.
func (s *Service) Status(ctx context.Context, key string) (View, error) {
	system, err := integrations.ParseKey(key)
	if err != nil {
		return View{}, err
	}
	_, appID, _ := integrations.LogicalID(key)
	v := View{Key: key, System: system, IntegrationID: appID, Transport: integrations.TransportREST, State: StateNotConfigured,
		Identity: map[string]any{}, Capabilities: map[string]any{}, KnownGaps: KnownGaps(system)}
	if s.agentBase != "" {
		v.AgentEndpoint = s.agentBase + "/gw/" + system + "/"
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
	st, _ := settingsFrom(integrations.Resolved{Integration: in, ConfigMap: cfg, Secrets: map[string]string{}})
	v.Endpoint, v.Auth = st.Base, st.Auth
	v.EndpointRefusal = s.guard.Refused(system, st.Base)
	v.EndpointPermitted = v.EndpointRefusal == ""
	var (
		version       time.Time
		state, detail string
		httpStatus    *int
		ident, caps   []byte
		attempt       time.Time
		success       *time.Time
		dur           int
	)
	err = s.pool.QueryRow(ctx, `SELECT config_version, state, detail, http_status, identity, capabilities, duration_ms, last_attempt_at, last_success_at
		FROM rest_connections WHERE integration_key = $1`, key).Scan(&version, &state, &detail, &httpStatus, &ident, &caps, &dur, &attempt, &success)
	if errors.Is(err, pgx.ErrNoRows) {
		v.State = StateSavedNotTested
		v.StateLabel = stateLabels[v.State]
		return v, nil
	}
	if err != nil {
		return v, err
	}
	v.State, v.Detail, v.HTTPStatus, v.DurationMS = state, detail, httpStatus, dur
	v.LastAttemptAt, v.LastSuccessAt = &attempt, success
	_ = json.Unmarshal(ident, &v.Identity)
	_ = json.Unmarshal(caps, &v.Capabilities)
	current := version.Equal(in.UpdatedAt)
	v.CapabilitiesCurrent = current && state == StateConnected
	if !current {
		v.State, v.LastCheckedState = StateSavedNotTested, state
		v.Detail = "the settings or a credential changed since the last check (" + stateLabels[state] + "); run Test connection"
	}
	v.StateLabel = stateLabels[v.State]
	return v, nil
}

// Register mounts GET /v1/integrations/{key}/check (auditor or security).
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/integrations/{key}/check", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := authz.Require(w, r, authz.RoleAuditor, authz.RoleSecurity); !ok {
			return
		}
		key := r.PathValue("key")
		if sys, err := integrations.ParseKey(key); err != nil || !isREST(sys) {
			httpx.WriteError(w, http.StatusBadRequest, "not a Salesforce, ServiceNow or SAP REST connection")
			return
		}
		v, err := s.Status(r.Context(), key)
		if err != nil {
			s.log.Error("saas rest status", "err", err)
			httpx.WriteError(w, http.StatusInternalServerError, "status failed (see server log)")
			return
		}
		httpx.WriteJSON(w, http.StatusOK, v)
	})
}

// KnownGaps of each REST connection type, as built and verified.
func KnownGaps(system string) []string {
	gaps := []string{
		"Fortik's gateway handling of this provider (decisions, holds, approvals, forwarding) was built and tested against a local fake of its API; a successful Test connection verifies the connection and credentials against your tenant, and each call agents make through the gateway is recorded with its decision.",
		"Only agents that call Fortik's gateway (/gw/" + system + "/...) with their Fortik token are governed; a client holding its own credentials is not seen.",
		"Writes and actions are held for approval and deletes are red holds: Fortik has no verified undo for this provider.",
	}
	switch system {
	case integrations.SystemSalesforce:
		gaps = append(gaps, "Native Agentforce actions run inside Salesforce and do not pass through Fortik: they are not blocked before execution.")
	case integrations.SystemSAP:
		gaps = append(gaps, "Endpoints and roles differ by SAP product; only the OData services listed are checked.")
	}
	return gaps
}
