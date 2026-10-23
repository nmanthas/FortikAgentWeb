// Package authz holds the caller identity shared by the API, the console
// session layer and the agent gateway.
package authz

import (
	"context"
	"net/http"
	"strings"

	"fortik/internal/httpx"
)

// Roles. "owner" is not a role: a user owns an agent when their email equals
// agents.sponsor (see IsOwner).
const (
	RoleAdmin       = "admin"
	RoleSecurity    = "security"
	RoleAuditor     = "auditor"
	RoleInterceptor = "interceptor"
)

// Kinds of principal.
const (
	KindToken = "token" // service bearer token (Phase 1)
	KindUser  = "user"  // human via OIDC / dev login session
	KindAgent = "agent" // agent authenticated with its agent token
)

type Principal struct {
	Kind       string          `json:"kind"`
	Name       string          `json:"name"`            // token name, agent id, or user display name
	Email      string          `json:"email,omitempty"` // users only
	Roles      map[string]bool `json:"-"`
	AuthMethod string          `json:"auth_method,omitempty"` // "token" | "oidc" | "dev" | "agent_token"
	InstanceID string          `json:"instance_id,omitempty"` // agents only
}

// Has reports whether the principal holds role (admin implies every role).
func (p Principal) Has(role string) bool { return p.Roles[role] || p.Roles[RoleAdmin] }

// Actor is the Diary actor string.
func (p Principal) Actor() string {
	switch p.Kind {
	case KindUser:
		return "user:" + p.Email
	case KindAgent:
		return "agent:" + p.Name
	default:
		return "token:" + p.Name
	}
}

// IsOwner reports whether a user principal is the sponsor of an agent.
func (p Principal) IsOwner(sponsor string) bool {
	return p.Kind == KindUser && p.Email != "" && sponsor != "" && equalFold(p.Email, sponsor)
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

type ctxKey struct{}

func With(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

func From(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(Principal)
	return p, ok
}

// Require returns the request's principal if it holds any of roles (admin
// always passes). It writes 401/403 and returns false otherwise. Handlers
// with data-dependent rules (owner checks) call From and decide themselves.
func Require(w http.ResponseWriter, r *http.Request, roles ...string) (Principal, bool) {
	p, ok := From(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return Principal{}, false
	}
	if len(roles) == 0 {
		return p, true
	}
	for _, role := range roles {
		if p.Has(role) {
			return p, true
		}
	}
	httpx.WriteError(w, http.StatusForbidden, "one of roles "+strings.Join(roles, ", ")+" required")
	return Principal{}, false
}
