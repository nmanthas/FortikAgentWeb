package integrations

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"fortik/internal/diary"
)

// Diary events of logical integrations.
const (
	EventAppCreated = "integration.app.created"
	EventAppUpdated = "integration.app.updated"
	EventAppDeleted = "integration.app.deleted"
)

// AppIntegration is one logical application integration: one tenant or
// account of one provider (e.g. netsuite:acme). Its transport connections
// are integrations rows linked to it.
type AppIntegration struct {
	IntegrationID     string    `json:"integration_id"`
	Provider          string    `json:"provider"`
	Environment       string    `json:"environment,omitempty"`
	TenantRef         string    `json:"tenant_ref,omitempty"` // account id (NetSuite full) or company label (QuickStart)
	DisplayName       string    `json:"display_name"`
	CreatedExplicitly bool      `json:"created_explicitly"`
	CreatedBy         string    `json:"created_by"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedBy         string    `json:"updated_by"`
	UpdatedAt         time.Time `json:"updated_at"`
}

const appCols = `integration_id, provider, environment, tenant_ref, display_name, created_explicitly, created_by, created_at, updated_by, updated_at`

func scanApp(row pgx.Row) (AppIntegration, error) {
	var a AppIntegration
	err := row.Scan(&a.IntegrationID, &a.Provider, &a.Environment, &a.TenantRef, &a.DisplayName, &a.CreatedExplicitly,
		&a.CreatedBy, &a.CreatedAt, &a.UpdatedBy, &a.UpdatedAt)
	a.CreatedAt, a.UpdatedAt = a.CreatedAt.UTC(), a.UpdatedAt.UTC()
	return a, err
}

// tenantRefFromConfig is the tenant identity a connection's settings name:
// the NetSuite account id (full accounts: REST and AI Connector Service
// connections must name the same account), or the QuickStart company label.
func tenantRefFromConfig(system string, cfg map[string]any) string {
	key, host := "", false
	switch system {
	case SystemNetSuite, SystemNetSuiteMCP:
		key = "account_id"
	case SystemNetSuiteQuickStart:
		key = "tenant_label"
	case SystemSalesforce, SystemSalesforceMCP, SystemServiceNow:
		key, host = "instance_url", true // the org's My Domain / the instance
	case SystemServiceNowMCP:
		key, host = "endpoint_url", true // served by the instance itself
	case SystemSAP:
		key, host = "api_base_url", true
	}
	if key == "" {
		return ""
	}
	v, _ := cfg[key].(string)
	v = strings.TrimSpace(v)
	if host && v != "" {
		u, err := url.Parse(v)
		if err != nil {
			return ""
		}
		return strings.ToLower(u.Host)
	}
	return v
}

// identityTenant: the tenant reference names the account itself (a NetSuite
// account id, a Salesforce org's My Domain, a ServiceNow instance, an SAP
// API host), so every connection of the integration must name the same one
// and it belongs to one integration only. A QuickStart company label is a
// display name, not an identity.
func identityTenant(environment string) bool { return environment != EnvNetSuiteQuickStart }

// linkApp finds or creates the logical integration of key inside tx and
// checks the connection fits it: same provider and environment, the same
// account (full NetSuite accounts), one connection per transport.
func (s *PGStore) linkApp(ctx context.Context, tx pgx.Tx, key, system string, cfg map[string]any, actor string) (string, string, error) {
	provider, appID, err := LogicalID(key)
	if err != nil {
		return "", "", err
	}
	m := connMeta[system]
	tenant := tenantRefFromConfig(system, cfg)
	app, err := scanApp(tx.QueryRow(ctx, `SELECT `+appCols+` FROM app_integrations WHERE integration_id = $1 FOR UPDATE`, appID))
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		display := tenant
		if display == "" {
			display = appID
		}
		if _, err := tx.Exec(ctx, `INSERT INTO app_integrations (integration_id, provider, environment, tenant_ref, display_name, created_by, updated_by)
			VALUES ($1, $2, $3, $4, $5, $6, $6)`, appID, provider, m.environment, tenant, display, actor); err != nil {
			return "", "", s.appConflict(ctx, err, provider, m.environment, tenant)
		}
	case err != nil:
		return "", "", fmt.Errorf("integrations: read %s: %w", appID, err)
	default:
		if app.Environment != m.environment {
			return "", "", invalid("%s is a %s %s integration; a %s connection needs a %s one (create a separate integration for it)",
				appID, envTitle(app.Environment), provider, system, envTitle(m.environment))
		}
		update := false
		switch {
		case tenant == "":
		case app.TenantRef == "":
			update = true
		case !strings.EqualFold(tenant, app.TenantRef):
			if identityTenant(m.environment) {
				return "", "", invalid("this connection names account %s but integration %s is account %s: connections of one integration must reach the same account (to move it, disconnect and connect again)",
					truncate(tenant, 40), appID, truncate(app.TenantRef, 40))
			}
			update = true // a QuickStart label is a name, not an identity
		}
		if update {
			if _, err := tx.Exec(ctx, `UPDATE app_integrations SET tenant_ref = $2, updated_by = $3, updated_at = now() WHERE integration_id = $1`,
				appID, tenant, actor); err != nil {
				return "", "", s.appConflict(ctx, err, provider, m.environment, tenant)
			}
		}
	}
	var other string
	err = tx.QueryRow(ctx, `SELECT key FROM integrations WHERE app_integration_id = $1 AND transport = $2 AND key <> $3`, appID, m.transport, key).Scan(&other)
	if err == nil {
		return "", "", invalid("integration %s already has a %s connection (%s)", appID, m.transport, other)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", "", err
	}
	return appID, m.transport, nil
}

// precheckApp runs linkApp's checks without writing, before any secret is
// stored (linkApp repeats them under the row lock).
func (s *PGStore) precheckApp(ctx context.Context, key, system string, cfg map[string]any) error {
	provider, appID, err := LogicalID(key)
	if err != nil {
		return err
	}
	m := connMeta[system]
	tenant := tenantRefFromConfig(system, cfg)
	app, err := s.GetApp(ctx, appID)
	switch {
	case errors.Is(err, ErrNotConfigured):
		if tenant != "" && identityTenant(m.environment) {
			var existing string
			err := s.pool.QueryRow(ctx, `SELECT integration_id FROM app_integrations WHERE provider = $1 AND environment = $2 AND lower(tenant_ref) = lower($3)`,
				provider, m.environment, tenant).Scan(&existing)
			if err == nil && existing != appID {
				return invalid("%s %s is already connected as integration %s: add this connection to it instead", provider, truncate(tenant, 40), existing)
			}
		}
		return nil
	case err != nil:
		return err
	}
	if app.Environment != m.environment {
		return invalid("%s is a %s %s integration; a %s connection needs a %s one (create a separate integration for it)",
			appID, envTitle(app.Environment), provider, system, envTitle(m.environment))
	}
	if identityTenant(m.environment) && tenant != "" && app.TenantRef != "" && !strings.EqualFold(tenant, app.TenantRef) {
		return invalid("this connection names account %s but integration %s is account %s: connections of one integration must reach the same account (to move it, disconnect and connect again)",
			truncate(tenant, 40), appID, truncate(app.TenantRef, 40))
	}
	return nil
}

// appConflict turns the tenant uniqueness violation into a clear error.
func (s *PGStore) appConflict(ctx context.Context, err error, provider, env, tenant string) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" {
		var existing string
		_ = s.pool.QueryRow(ctx, `SELECT integration_id FROM app_integrations WHERE provider = $1 AND environment = $2 AND lower(tenant_ref) = lower($3)`,
			provider, env, tenant).Scan(&existing)
		return invalid("%s %s is already connected as integration %s: add this connection to it instead", provider, truncate(tenant, 40), existing)
	}
	return err
}

func envTitle(env string) string {
	switch env {
	case EnvNetSuiteFull:
		return "full NetSuite"
	case EnvNetSuiteQuickStart:
		return "NetSuite QuickStart"
	case "":
		return "standard"
	}
	return env
}

// CreateAppInput is the body of POST /v1/app-integrations.
type CreateAppInput struct {
	Provider    string `json:"provider"`
	Environment string `json:"environment"`
	Name        string `json:"name"` // the instance part of the id: netsuite:<name>
	TenantRef   string `json:"tenant_ref"`
	DisplayName string `json:"display_name"`
}

// CreateApp creates a logical integration ahead of its connections (e.g. a
// second NetSuite account). Only providers with several transports or
// environments need this; others are created with their connection.
func (s *PGStore) CreateApp(ctx context.Context, in CreateAppInput, actor string) (AppIntegration, error) {
	p, ok := providerByID(in.Provider)
	if !ok {
		return AppIntegration{}, invalid("unknown provider %q", truncate(in.Provider, 40))
	}
	env, ok := p.environment(in.Environment)
	if !ok {
		return AppIntegration{}, invalid("%s has no environment %q", p.Provider, truncate(in.Environment, 40))
	}
	if !postgresName.MatchString(in.Name) {
		return AppIntegration{}, invalid("name must match ^[a-z][a-z0-9_]{0,62}$ (it becomes %s:<name>)", p.Provider)
	}
	in.TenantRef, in.DisplayName = strings.TrimSpace(in.TenantRef), strings.TrimSpace(in.DisplayName)
	if err := checkLabel(in.DisplayName, 100); err != nil || in.DisplayName == "" {
		return AppIntegration{}, invalid("display_name is required (at most 100 characters)")
	}
	if in.TenantRef != "" {
		switch {
		case env.Environment == EnvNetSuiteFull:
			if err := match(netsuiteAccount, in.TenantRef, "a NetSuite account ID such as 1234567 or 1234567_SB1"); err != nil {
				return AppIntegration{}, invalid("tenant_ref: %v", err)
			}
		case p.Provider == ProviderSalesforce || p.Provider == ProviderServiceNow || p.Provider == ProviderSAP:
			// the org's My Domain / the instance / the API host, as a URL or a host name
			host := in.TenantRef
			if u, err := url.Parse(in.TenantRef); err == nil && u.Host != "" {
				host = u.Host
			}
			if err := checkHost(strings.ToLower(host)); err != nil {
				return AppIntegration{}, invalid("tenant_ref: %v", err)
			}
			in.TenantRef = strings.ToLower(host)
		default:
			if err := checkLabel(in.TenantRef, 100); err != nil {
				return AppIntegration{}, invalid("tenant_ref: %v", err)
			}
		}
	}
	id := p.Provider + ":" + in.Name
	var out AppIntegration
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		out, err = scanApp(tx.QueryRow(ctx, `INSERT INTO app_integrations (integration_id, provider, environment, tenant_ref, display_name, created_explicitly, created_by, updated_by)
			VALUES ($1, $2, $3, $4, $5, true, $6, $6) RETURNING `+appCols, id, p.Provider, env.Environment, in.TenantRef, in.DisplayName, actor))
		if err != nil {
			var pe *pgconn.PgError
			if errors.As(err, &pe) && pe.Code == "23505" && pe.ConstraintName == "app_integrations_pkey" {
				return invalid("integration %s already exists", id)
			}
			return s.appConflict(ctx, err, p.Provider, env.Environment, in.TenantRef)
		}
		_, err = s.diary.AppendTx(ctx, tx, diary.Event{EventType: EventAppCreated, Actor: actor, Data: map[string]any{
			"integration_id": id, "provider": p.Provider, "environment": env.Environment, "tenant_ref": in.TenantRef, "display_name": in.DisplayName}})
		return err
	})
	return out, err
}

// GetApp returns one logical integration (ErrNotConfigured if absent).
func (s *PGStore) GetApp(ctx context.Context, id string) (AppIntegration, error) {
	a, err := scanApp(s.pool.QueryRow(ctx, `SELECT `+appCols+` FROM app_integrations WHERE integration_id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return AppIntegration{}, fmt.Errorf("%w: %s", ErrNotConfigured, truncate(id, 80))
	}
	return a, err
}

// ListApps returns every logical integration, ordered by id.
func (s *PGStore) ListApps(ctx context.Context) ([]AppIntegration, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+appCols+` FROM app_integrations ORDER BY integration_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AppIntegration
	for rows.Next() {
		a, err := scanApp(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// UpdateApp renames a logical integration.
func (s *PGStore) UpdateApp(ctx context.Context, id, displayName, actor string) (AppIntegration, error) {
	displayName = strings.TrimSpace(displayName)
	if err := checkLabel(displayName, 100); err != nil || displayName == "" {
		return AppIntegration{}, invalid("display_name is required (at most 100 characters)")
	}
	var out AppIntegration
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		out, err = scanApp(tx.QueryRow(ctx, `UPDATE app_integrations SET display_name = $2, updated_by = $3, updated_at = now()
			WHERE integration_id = $1 RETURNING `+appCols, id, displayName, actor))
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: %s", ErrNotConfigured, truncate(id, 80))
		}
		if err != nil {
			return err
		}
		_, err = s.diary.AppendTx(ctx, tx, diary.Event{EventType: EventAppUpdated, Actor: actor, Data: map[string]any{"integration_id": id, "display_name": displayName}})
		return err
	})
	return out, err
}

// ErrHasConnections: a logical integration with connections cannot be deleted.
var ErrHasConnections = errors.New("the integration still has connections: disconnect them first")

// DeleteApp deletes a logical integration that has no connections.
func (s *PGStore) DeleteApp(ctx context.Context, id, actor string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM integrations WHERE app_integration_id = $1`, id).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return ErrHasConnections
		}
		tag, err := tx.Exec(ctx, `DELETE FROM app_integrations WHERE integration_id = $1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("%w: %s", ErrNotConfigured, truncate(id, 80))
		}
		_, err = s.diary.AppendTx(ctx, tx, diary.Event{EventType: EventAppDeleted, Actor: actor, Data: map[string]any{"integration_id": id}})
		return err
	})
}

// ConnectionsOf returns a logical integration's connections.
func (s *PGStore) ConnectionsOf(ctx context.Context, id string) ([]Integration, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+rowCols+` FROM integrations WHERE app_integration_id = $1 ORDER BY transport, key`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Integration
	for rows.Next() {
		in, err := scanRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

// ConnectionFor returns the key of a logical integration's connection over
// one transport (ErrNotConfigured if it has none).
func (s *PGStore) ConnectionFor(ctx context.Context, id, transport string) (Integration, error) {
	in, err := scanRow(s.pool.QueryRow(ctx, `SELECT `+rowCols+` FROM integrations WHERE app_integration_id = $1 AND transport = $2`, id, transport))
	if errors.Is(err, pgx.ErrNoRows) {
		return Integration{}, fmt.Errorf("%w: %s has no %s connection", ErrNotConfigured, truncate(id, 80), transport)
	}
	return in, err
}

// --- Disconnect: before-delete hooks ------------------------------------------

// BeforeDeleteHook runs before a connection's secrets are deleted (e.g. to
// revoke an OAuth grant with the provider). It returns a note for the
// administrator ("" for nothing to say); it must not block the delete.
type BeforeDeleteHook func(ctx context.Context, key, actor string) string

var beforeHooksMu sync.Mutex

// OnBeforeDelete registers a hook for Disconnect.
func (s *PGStore) OnBeforeDelete(fn BeforeDeleteHook) {
	beforeHooksMu.Lock()
	defer beforeHooksMu.Unlock()
	s.beforeDelete = append(s.beforeDelete, fn)
}

// Disconnect runs the before-delete hooks, then deletes the connection's
// secrets and settings. The notes say what the hooks did (e.g. whether an
// upstream grant was revoked); a hook never stops the delete.
func (s *PGStore) Disconnect(ctx context.Context, key, actor string) ([]string, error) {
	if _, err := ParseKey(key); err != nil {
		return nil, err
	}
	if _, err := getRow(ctx, s.pool, key); err != nil {
		return nil, err
	}
	beforeHooksMu.Lock()
	hooks := slices.Clone(s.beforeDelete)
	beforeHooksMu.Unlock()
	notes := []string{}
	for _, fn := range hooks {
		if n := fn(ctx, key, actor); n != "" {
			notes = append(notes, n)
		}
	}
	return notes, s.Delete(ctx, key, actor)
}
