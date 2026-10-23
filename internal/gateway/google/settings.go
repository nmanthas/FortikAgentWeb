package google

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/gateway"
	"fortik/internal/integrations"
)

// IntegrationKey is the integrations row (and system) this adapter uses.
const IntegrationKey = "google_workspace"

// settings is the resolved google_workspace integration (config + secret).
type settings struct {
	primaryDomain string
	internal      map[string]bool // lower-cased; includes primaryDomain
	testUser      string
	saJSON        []byte
	fingerprint   string // sha256 prefix of the service account JSON (cache key, never logged as secret)
}

// parseSettings validates an integration as configured in the console.
// Missing required fields mean "not configured" (fail closed).
func parseSettings(r integrations.Resolved) (settings, error) {
	s := settings{internal: map[string]bool{}}
	s.primaryDomain = normDomain(str(r.ConfigMap["primary_domain"]))
	if s.primaryDomain == "" {
		return settings{}, fmt.Errorf("%w: google_workspace.primary_domain is not set", integrations.ErrNotConfigured)
	}
	s.internal[s.primaryDomain] = true
	for _, d := range list(r.ConfigMap["internal_domains"]) {
		if d = normDomain(d); d != "" {
			s.internal[d] = true
		}
	}
	s.testUser = strings.ToLower(strings.TrimSpace(str(r.ConfigMap["test_user"])))
	sa := strings.TrimSpace(r.Secrets["service_account_json"])
	if sa == "" {
		return settings{}, fmt.Errorf("%w: google_workspace.service_account_json is not set", integrations.ErrNotConfigured)
	}
	var probe struct {
		Type        string `json:"type"`
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
	}
	if err := json.Unmarshal([]byte(sa), &probe); err != nil || probe.Type != "service_account" || probe.ClientEmail == "" || probe.PrivateKey == "" {
		return settings{}, fmt.Errorf("%w: google_workspace.service_account_json is not a service account key", integrations.ErrInvalid)
	}
	s.saJSON = []byte(sa)
	sum := sha256.Sum256(s.saJSON)
	s.fingerprint = hex.EncodeToString(sum[:8])
	return s, nil
}

func (s settings) isInternal(domain string) bool { return s.internal[normDomain(domain)] }

func normDomain(d string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// list accepts a JSON list of strings or a comma/newline separated string.
func list(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return strings.FieldsFunc(t, func(r rune) bool { return r == ',' || r == '\n' || r == ' ' })
	}
	return nil
}

// settings loads the current integration. integrations.ErrNotConfigured (or
// an invalid integration) is reported as a gateway.NotConfiguredError.
func (a *Adapter) settings(ctx context.Context) (settings, error) {
	if a.src == nil {
		return settings{}, &gateway.NotConfiguredError{System: IntegrationKey}
	}
	r, err := a.src.Get(ctx, IntegrationKey)
	if errors.Is(err, integrations.ErrNotConfigured) {
		return settings{}, &gateway.NotConfiguredError{System: IntegrationKey}
	}
	if err != nil {
		return settings{}, fmt.Errorf("load google_workspace integration: %w", err)
	}
	s, err := parseSettings(r)
	if errors.Is(err, integrations.ErrNotConfigured) || errors.Is(err, integrations.ErrInvalid) {
		a.log.Warn("google_workspace integration unusable", "err", err)
		return settings{}, &gateway.NotConfiguredError{System: IntegrationKey}
	}
	return s, err
}

// AgentDirectory resolves an agent's Google Workspace identity (the mailbox
// the gateway impersonates by domain-wide delegation). "" means none.
type AgentDirectory interface {
	WorkspaceUser(ctx context.Context, agentID string) (string, error)
}

// PGDirectory reads agents.workspace_user. It is not cached, so a change made
// in the console applies to the next request.
type PGDirectory struct{ Pool *pgxpool.Pool }

func (d PGDirectory) WorkspaceUser(ctx context.Context, agentID string) (string, error) {
	var u string
	err := d.Pool.QueryRow(ctx, `SELECT workspace_user FROM agents WHERE agent_id = $1`, agentID).Scan(&u)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("workspace user for %s: %w", agentID, err)
	}
	return strings.ToLower(strings.TrimSpace(u)), nil
}
