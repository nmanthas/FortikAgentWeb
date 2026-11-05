package integrations

import (
	"context"
	"errors"
	"net/http"
	"time"

	"fortik/internal/authz"
	"fortik/internal/httpx"
)

// Overall health of a logical integration, from its connections.
const (
	HealthNotConnected = "not_connected" // no connection configured
	HealthHealthy      = "healthy"       // every configured connection passed its last test
	HealthDegraded     = "degraded"      // some passed, some failed or are untested
	HealthUnhealthy    = "unhealthy"     // none passed and at least one failed
	HealthUntested     = "untested"      // configured, never tested
)

// TransportView is one transport of a logical integration: what the
// provider environment offers and the connection configured for it.
type TransportView struct {
	TransportOption
	ConnectionKey string `json:"connection_key"` // the key to configure (PUT /v1/integrations/{key})
	Configured    bool   `json:"configured"`
	Status        string `json:"status,omitempty"` // configured | ok | error
}

// AppView is GET /v1/app-integrations[/{id}].
type AppView struct {
	AppIntegration
	ProviderTitle    string          `json:"provider_title"`
	EnvironmentTitle string          `json:"environment_title,omitempty"`
	Health           string          `json:"health"`
	Connections      []View          `json:"connections"`
	Transports       []TransportView `json:"transports"`
}

func health(conns []Integration) string {
	if len(conns) == 0 {
		return HealthNotConnected
	}
	ok, bad, untested := 0, 0, 0
	for _, c := range conns {
		switch c.Status {
		case StatusOK:
			ok++
		case StatusError:
			bad++
		default:
			untested++
		}
	}
	switch {
	case ok == len(conns):
		return HealthHealthy
	case ok > 0:
		return HealthDegraded
	case bad > 0:
		return HealthUnhealthy
	}
	return HealthUntested
}

func (h *Handler) appView(ctx context.Context, a AppIntegration) (AppView, error) {
	conns, err := h.store.ConnectionsOf(ctx, a.IntegrationID)
	if err != nil {
		return AppView{}, err
	}
	v := AppView{AppIntegration: a, Health: health(conns), Connections: []View{}, Transports: []TransportView{}}
	for _, c := range conns {
		v.Connections = append(v.Connections, h.view(c))
	}
	if p, ok := providerByID(a.Provider); ok {
		v.ProviderTitle = p.Title
		if env, ok := p.environment(a.Environment); ok {
			v.EnvironmentTitle = env.Title
			for _, o := range env.Transports {
				tv := TransportView{TransportOption: o}
				if o.System != "" {
					tv.ConnectionKey, _ = ConnectionKey(o.System, a.IntegrationID)
				}
				for _, c := range conns {
					if c.Transport == o.Transport {
						tv.Configured, tv.Status, tv.ConnectionKey = true, c.Status, c.Key
					}
				}
				v.Transports = append(v.Transports, tv)
			}
		}
	}
	return v, nil
}

// registerApps mounts:
//
//	GET    /v1/app-integrations               auditor|security  logical integrations, their connections and transports
//	POST   /v1/app-integrations               security          create a tenant (multi-tenant providers)
//	GET    /v1/app-integrations/{id}          auditor|security
//	PATCH  /v1/app-integrations/{id}          security          rename
//	DELETE /v1/app-integrations/{id}          security          only without connections
//	GET    /v1/app-integrations/{id}/activity auditor|security  last 24h of agents' calls across its transports
func (h *Handler) registerApps(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/app-integrations", h.listApps)
	mux.HandleFunc("POST /v1/app-integrations", h.createApp)
	mux.HandleFunc("GET /v1/app-integrations/{id}", h.getApp)
	mux.HandleFunc("PATCH /v1/app-integrations/{id}", h.updateApp)
	mux.HandleFunc("DELETE /v1/app-integrations/{id}", h.deleteApp)
	mux.HandleFunc("GET /v1/app-integrations/{id}/activity", h.appActivity)
}

func (h *Handler) listApps(w http.ResponseWriter, r *http.Request) {
	if _, ok := authz.Require(w, r, authz.RoleAuditor, authz.RoleSecurity); !ok {
		return
	}
	apps, err := h.store.ListApps(r.Context())
	if err != nil {
		h.internal(w, "list integrations", err)
		return
	}
	out := make([]AppView, 0, len(apps))
	for _, a := range apps {
		v, err := h.appView(r.Context(), a)
		if err != nil {
			h.internal(w, "list integrations", err)
			return
		}
		out = append(out, v)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"integrations": out, "providers": Providers()})
}

func (h *Handler) getApp(w http.ResponseWriter, r *http.Request) {
	if _, ok := authz.Require(w, r, authz.RoleAuditor, authz.RoleSecurity); !ok {
		return
	}
	a, err := h.store.GetApp(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, "get integration", err)
		return
	}
	v, err := h.appView(r.Context(), a)
	if err != nil {
		h.internal(w, "get integration", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}

func (h *Handler) createApp(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.Require(w, r, authz.RoleSecurity)
	if !ok {
		return
	}
	var in CreateAppInput
	if err := httpx.DecodeStrict(r, &in, 16<<10); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, `invalid JSON body: want {"provider","environment","name","tenant_ref","display_name"}`)
		return
	}
	a, err := h.store.CreateApp(r.Context(), in, p.Actor())
	if err != nil {
		h.fail(w, "create integration", err)
		return
	}
	v, err := h.appView(r.Context(), a)
	if err != nil {
		h.internal(w, "create integration", err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, v)
}

func (h *Handler) updateApp(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.Require(w, r, authz.RoleSecurity)
	if !ok {
		return
	}
	var in struct {
		DisplayName string `json:"display_name"`
	}
	if err := httpx.DecodeStrict(r, &in, 4<<10); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, `invalid JSON body: want {"display_name"}`)
		return
	}
	a, err := h.store.UpdateApp(r.Context(), r.PathValue("id"), in.DisplayName, p.Actor())
	if err != nil {
		h.fail(w, "update integration", err)
		return
	}
	v, err := h.appView(r.Context(), a)
	if err != nil {
		h.internal(w, "update integration", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, v)
}

func (h *Handler) deleteApp(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.Require(w, r, authz.RoleSecurity)
	if !ok {
		return
	}
	err := h.store.DeleteApp(r.Context(), r.PathValue("id"), p.Actor())
	if errors.Is(err, ErrHasConnections) {
		httpx.WriteError(w, http.StatusConflict, err.Error())
		return
	}
	if err != nil {
		h.fail(w, "delete integration", err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": r.PathValue("id")})
}

// ActivityRow is one decided call of an agent through one of the
// integration's transports.
type ActivityRow struct {
	ActionID  string    `json:"action_id"`
	AgentID   string    `json:"agent_id"`
	Transport string    `json:"transport"`
	Operation string    `json:"operation"` // MCP tool or REST operation
	Decision  string    `json:"decision"`
	RuleID    string    `json:"rule_id"`
	Reason    string    `json:"reason"`
	TS        time.Time `json:"ts"`
}

// AppActivity is GET /v1/app-integrations/{id}/activity.
type AppActivity struct {
	IntegrationID     string                    `json:"integration_id"`
	WindowHours       int                       `json:"window_hours"`
	ByTransport       map[string]map[string]int `json:"by_transport"` // transport -> decision -> count
	PendingApprovals  int                       `json:"pending_approvals"`
	ActiveSuspensions int                       `json:"active_suspensions"` // timed suspensions of the provider's business systems
	Recent            []ActivityRow             `json:"recent"`
}

// businessSystems are the action systems a provider's calls are decided as.
func businessSystems(provider string) []string {
	switch provider {
	case SystemGoogle:
		return []string{"gmail", "drive"}
	}
	return []string{provider}
}

func (h *Handler) appActivity(w http.ResponseWriter, r *http.Request) {
	if _, ok := authz.Require(w, r, authz.RoleAuditor, authz.RoleSecurity); !ok {
		return
	}
	ctx := r.Context()
	a, err := h.store.GetApp(ctx, r.PathValue("id"))
	if err != nil {
		h.fail(w, "integration activity", err)
		return
	}
	out := AppActivity{IntegrationID: a.IntegrationID, WindowHours: 24, ByTransport: map[string]map[string]int{}, Recent: []ActivityRow{}}
	pool := h.store.pool
	rows, err := pool.Query(ctx, `SELECT COALESCE(target ->> 'transport', ''), decision, count(*) FROM actions
		WHERE target ->> 'integration_id' = $1 AND ts > now() - interval '24 hours' GROUP BY 1, 2`, a.IntegrationID)
	if err != nil {
		h.internal(w, "integration activity", err)
		return
	}
	for rows.Next() {
		var t, d string
		var n int
		if err := rows.Scan(&t, &d, &n); err != nil {
			rows.Close()
			h.internal(w, "integration activity", err)
			return
		}
		if out.ByTransport[t] == nil {
			out.ByTransport[t] = map[string]int{}
		}
		out.ByTransport[t][d] += n
	}
	rows.Close()
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM held_actions h JOIN actions a USING (action_id)
		WHERE h.outcome = 'pending' AND h.expires_at > now() AND a.target ->> 'integration_id' = $1`, a.IntegrationID).Scan(&out.PendingApprovals); err != nil {
		h.internal(w, "integration activity", err)
		return
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM access_overrides WHERE system = ANY($1) AND status IN ('active', 'blocked')
		AND (expires_at IS NULL OR expires_at > now())`, businessSystems(a.Provider)).Scan(&out.ActiveSuspensions); err != nil {
		h.internal(w, "integration activity", err)
		return
	}
	rows, err = pool.Query(ctx, `SELECT action_id, agent_id, COALESCE(target ->> 'transport', ''),
			COALESCE(target ->> 'tool', target ->> 'operation', ''), decision, rule_id, reason, ts
		FROM actions WHERE target ->> 'integration_id' = $1 AND ts > now() - interval '24 hours' ORDER BY ts DESC LIMIT 20`, a.IntegrationID)
	if err != nil {
		h.internal(w, "integration activity", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var x ActivityRow
		if err := rows.Scan(&x.ActionID, &x.AgentID, &x.Transport, &x.Operation, &x.Decision, &x.RuleID, &x.Reason, &x.TS); err != nil {
			h.internal(w, "integration activity", err)
			return
		}
		x.Reason = truncate(x.Reason, 240)
		out.Recent = append(out.Recent, x)
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
