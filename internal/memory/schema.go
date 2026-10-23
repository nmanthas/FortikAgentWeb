package memory

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/broker/pgroles"
	"fortik/internal/integrations"
	"fortik/internal/pgsql"
)

// System is the integration system and the Action system of the memory gateway.
const System = "memory"

// KeyPrefix is the integration key prefix: memory:<name>.
const KeyPrefix = System + ":"

// Schema name and items table inside the customer's database.
const (
	DBSchema   = "fortik_memory"
	ItemsTable = "items"
)

// MaxDimension is pgvector's limit for the vector type.
const MaxDimension = 16000

var storeName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

// ValidStoreName reports whether name is a valid <name> in memory:<name>
// (matches the integrations key CHECK constraint).
func ValidStoreName(name string) bool { return storeName.MatchString(name) }

// IntegrationKey returns memory:<name>.
func IntegrationKey(name string) string { return KeyPrefix + name }

// StoreNameFromKey returns <name> for memory:<name>.
func StoreNameFromKey(key string) (string, error) {
	name, ok := strings.CutPrefix(key, KeyPrefix)
	if !ok || !ValidStoreName(name) {
		return "", fmt.Errorf("%w: memory store keys are memory:<name> with name matching %s", integrations.ErrInvalid, storeName)
	}
	return name, nil
}

// Schema is the "memory" integration type for the Integrations screen. Its
// single definition lives in the integrations package (which cannot import
// this one). Fortik logs in as admin_user to create schema fortik_memory, the
// items table and snapshot tables in the customer's database; agents never
// receive these credentials.
func Schema() integrations.Schema {
	s, _ := integrations.SchemaFor(integrations.SystemMemory)
	return s
}

// Settings are the parsed connection settings of one memory:<name> store.
type Settings struct {
	Key       string
	Name      string
	Host      string
	Port      int
	Database  string
	SSLMode   string
	AdminUser string
	Dimension int
	password  string
}

// String keeps the password out of logs.
func (s Settings) String() string {
	return fmt.Sprintf("memory store %s (%s@%s:%d/%s)", s.Key, s.AdminUser, s.Host, s.Port, s.Database)
}

// GoString keeps the password out of %#v.
func (s Settings) GoString() string { return s.String() }

var sslModes = map[string]bool{"disable": true, "allow": true, "prefer": true, "require": true, "verify-ca": true, "verify-full": true}

// ParseSettings validates a resolved memory:<name> integration.
func ParseSettings(r integrations.Resolved) (Settings, error) {
	name, err := StoreNameFromKey(r.Key)
	if err != nil {
		return Settings{}, err
	}
	s := Settings{Key: r.Key, Name: name, Host: strings.TrimSpace(r.Text("host")), Port: r.Int("port"),
		Database: strings.TrimSpace(r.Text("database")), SSLMode: r.Text("sslmode"), AdminUser: strings.TrimSpace(r.Text("admin_user")),
		Dimension: r.Int("dimension"), password: r.Secret("admin_password")}
	if s.Port == 0 {
		s.Port = 5432
	}
	if s.SSLMode == "" {
		s.SSLMode = "require"
	}
	var problems []string
	if s.Host == "" {
		problems = append(problems, "host is required")
	}
	if s.Database == "" {
		problems = append(problems, "database is required")
	}
	if s.AdminUser == "" {
		problems = append(problems, "admin_user is required")
	}
	if s.Port < 1 || s.Port > 65535 {
		problems = append(problems, "port must be in 1..65535")
	}
	if !sslModes[s.SSLMode] {
		problems = append(problems, "sslmode must be one of disable|allow|prefer|require|verify-ca|verify-full")
	}
	if s.Dimension < 0 || s.Dimension > MaxDimension {
		problems = append(problems, fmt.Sprintf("dimension must be between 1 and %d (or empty)", MaxDimension))
	}
	if len(problems) > 0 {
		return Settings{}, fmt.Errorf("%w: %s: %s", integrations.ErrInvalid, r.Key, strings.Join(problems, "; "))
	}
	return s, nil
}

// connConfig builds the admin connection config. search_path is pinned to
// pg_catalog: every object Fortik touches is schema-qualified, so objects a
// customer role created elsewhere can never shadow them.
func (s Settings) connConfig() (*pgconn.Config, error) {
	return pgroles.BuildConnConfig(s.Host, s.Port, s.Database, s.AdminUser, s.password, s.SSLMode,
		map[string]string{"application_name": "fortik:memory", "search_path": "pg_catalog"})
}

// poolConfig builds a small pool config for the store.
func (s Settings) poolConfig() (*pgxpool.Config, error) {
	pc, err := s.connConfig()
	if err != nil {
		return nil, err
	}
	cfg, err := pgxpool.ParseConfig("")
	if err != nil {
		return nil, err
	}
	cfg.ConnConfig.Config = *pc
	cfg.MaxConns = 4
	return cfg, nil
}

// Tester implements integrations.Tester for memory:<name>. It logs in as the
// admin user and checks that the vector extension is installed (or can be
// installed) and that schema fortik_memory exists and is usable (or can be
// created). Errors are safe to show in the UI: they never contain secrets.
type Tester struct{}

var _ integrations.Tester = Tester{}

func (Tester) System() string { return System }

func (Tester) Test(ctx context.Context, r integrations.Resolved) error {
	s, err := ParseSettings(r)
	if err != nil {
		return err
	}
	pc, err := s.connConfig()
	if err != nil {
		return err
	}
	cc, err := pgx.ParseConfig("")
	if err != nil {
		return err
	}
	cc.Config = *pc
	cctx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	conn, err := pgx.ConnectConfig(cctx, cc)
	if err != nil {
		return fmt.Errorf("connect as %s to %s:%d/%s failed: %s", s.AdminUser, s.Host, s.Port, s.Database, sanitize(err))
	}
	defer conn.Close(context.WithoutCancel(ctx))

	var (
		installed, available, super, dbCreate, schemaExists, schemaUsage, schemaCreate bool
	)
	err = conn.QueryRow(ctx, `SELECT
       EXISTS (SELECT 1 FROM pg_catalog.pg_extension WHERE extname = 'vector'),
       EXISTS (SELECT 1 FROM pg_catalog.pg_available_extensions WHERE name = 'vector'),
       (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user),
       pg_catalog.has_database_privilege(current_database(), 'CREATE'),
       pg_catalog.to_regnamespace($1) IS NOT NULL`, pgsql.QuoteIdent(DBSchema)).
		Scan(&installed, &available, &super, &dbCreate, &schemaExists)
	if err != nil {
		return fmt.Errorf("inspect database: %s", sanitize(err))
	}
	var problems []string
	switch {
	case installed:
	case !available:
		problems = append(problems, "the pgvector extension is not available on this server (install pgvector, then CREATE EXTENSION vector)")
	case !super:
		// Non-superusers may install only trusted extensions; pgvector is
		// not marked trusted by default.
		problems = append(problems, fmt.Sprintf("the vector extension is not installed in %s and %q is not a superuser: run CREATE EXTENSION vector as a superuser", s.Database, s.AdminUser))
	}
	if schemaExists {
		if err := conn.QueryRow(ctx, `SELECT pg_catalog.has_schema_privilege($1::regnamespace, 'USAGE'),
       pg_catalog.has_schema_privilege($1::regnamespace, 'CREATE')`, pgsql.QuoteIdent(DBSchema)).Scan(&schemaUsage, &schemaCreate); err != nil {
			return fmt.Errorf("inspect schema privileges: %s", sanitize(err))
		}
		if !schemaUsage || !schemaCreate {
			problems = append(problems, fmt.Sprintf("%q needs USAGE and CREATE on schema %s (snapshots are tables in it)", s.AdminUser, DBSchema))
		}
	} else if !dbCreate {
		problems = append(problems, fmt.Sprintf("schema %s does not exist and %q may not create it (GRANT CREATE ON DATABASE %s TO %s, or CREATE SCHEMA %s AUTHORIZATION %s)",
			DBSchema, s.AdminUser, pgsql.QuoteIdent(s.Database), pgsql.QuoteIdent(s.AdminUser), DBSchema, pgsql.QuoteIdent(s.AdminUser)))
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// sanitize keeps a driver error short, single-line and free of connection
// strings.
func sanitize(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code + ": " + truncate(pgErr.Message, 200)
	}
	return truncate(strings.Join(strings.Fields(err.Error()), " "), 300)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n] + "..."
}
