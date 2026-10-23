package pgroles

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"fortik/internal/config"
	"fortik/internal/integrations"
)

// System is the integration system and broker system handled here.
const System = "postgres"

// KeyPrefix prefixes Postgres integration keys ("postgres:<name>").
const KeyPrefix = System + ":"

// connectTimeout bounds every upstream login (admin and per-agent).
const connectTimeout = 15 * time.Second

// upstreamName mirrors the integrations.key CHECK constraint (migration 0003).
var upstreamName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

// ErrUpstreamNotManaged means no postgres:<name> integration exists for the
// upstream. pgproxy and pgundo then fall back to the YAML ("legacy") upstream;
// every other resolution error is fatal for the request (fail closed).
var ErrUpstreamNotManaged = errors.New("postgres upstream is not configured as an integration")

// ValidName reports whether name can be a Postgres integration upstream name.
func ValidName(name string) bool { return upstreamName.MatchString(name) }

// Key returns the integration key of an upstream ("postgres:<name>").
func Key(name string) string { return KeyPrefix + name }

// NameFromKey accepts "acme_prod" or "postgres:acme_prod" and returns the
// upstream name, or an error when it is not a valid name.
func NameFromKey(key string) (string, error) {
	name := strings.TrimPrefix(key, KeyPrefix)
	if !ValidName(name) {
		return "", fmt.Errorf("%w: invalid postgres upstream name %q", integrations.ErrInvalid, name)
	}
	return name, nil
}

// Upstream is one integration-backed upstream (postgres:<name>) resolved for
// in-process use. The admin password is unexported and never printed: String,
// GoString and LogValue redact it, and it is not marshalled to JSON.
type Upstream struct {
	Name        string `json:"name"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Database    string `json:"database"`
	SSLMode     string `json:"sslmode"`
	Environment string `json:"environment"`
	AdminUser   string `json:"admin_user"`
	ReadRole    string `json:"read_role"`
	WriteRole   string `json:"write_role"`

	adminPassword string
}

func (u Upstream) String() string {
	return fmt.Sprintf("postgres:%s(%s@%s:%d/%s)", u.Name, u.AdminUser, u.Host, u.Port, u.Database)
}

// GoString keeps %#v from printing the admin password.
func (u Upstream) GoString() string { return u.String() }

// LogValue keeps slog from printing the admin password.
func (u Upstream) LogValue() slog.Value {
	return slog.GroupValue(slog.String("upstream", u.Name), slog.String("host", u.Host),
		slog.Int("port", u.Port), slog.String("database", u.Database), slog.String("environment", u.Environment))
}

var sslModes = map[string]bool{"disable": true, "allow": true, "prefer": true, "require": true, "verify-ca": true, "verify-full": true}

// ParseUpstream validates a resolved postgres:<name> integration. Unknown or
// missing required settings are an error (fail closed); the error never
// contains a secret value.
func ParseUpstream(r integrations.Resolved) (Upstream, error) {
	name, err := NameFromKey(r.Key)
	if err != nil {
		return Upstream{}, err
	}
	if r.System != "" && r.System != System {
		return Upstream{}, fmt.Errorf("%w: integration %s has system %q", integrations.ErrInvalid, r.Key, r.System)
	}
	cm := r.ConfigMap
	if cm == nil && len(r.Config) > 0 {
		if err := json.Unmarshal(r.Config, &cm); err != nil {
			return Upstream{}, fmt.Errorf("%w: integration %s config is not a JSON object", integrations.ErrInvalid, r.Key)
		}
	}
	u := Upstream{Name: name}
	var problems []string
	str := func(k string, required bool) string {
		v, ok := cm[k]
		if !ok || v == nil {
			if required {
				problems = append(problems, k+" is required")
			}
			return ""
		}
		s, ok := v.(string)
		if !ok {
			problems = append(problems, k+" must be a string")
			return ""
		}
		s = strings.TrimSpace(s)
		if s == "" && required {
			problems = append(problems, k+" is required")
		}
		return s
	}
	u.Host = str("host", true)
	u.Database = str("database", true)
	u.SSLMode = str("sslmode", false)
	u.Environment = str("environment", true)
	u.AdminUser = str("admin_user", true)
	u.ReadRole = str("read_role", true)
	u.WriteRole = str("write_role", true)
	port, err := portValue(cm["port"])
	if err != nil {
		problems = append(problems, err.Error())
	}
	u.Port = port
	if u.SSLMode == "" {
		u.SSLMode = "prefer"
	}
	if !sslModes[u.SSLMode] {
		problems = append(problems, "sslmode must be one of disable|allow|prefer|require|verify-ca|verify-full")
	}
	switch u.Environment {
	case "", "prod", "staging", "dev":
	default:
		problems = append(problems, "environment must be prod|staging|dev")
	}
	if u.ReadRole != "" && u.ReadRole == u.WriteRole {
		problems = append(problems, "read_role and write_role must differ")
	}
	if u.AdminUser != "" && (u.AdminUser == u.ReadRole || u.AdminUser == u.WriteRole) {
		problems = append(problems, "admin_user must differ from read_role and write_role")
	}
	for _, role := range []string{u.ReadRole, u.WriteRole} {
		if strings.HasPrefix(role, rolePrefix) {
			problems = append(problems, "read_role/write_role must not be Fortik-managed agent roles")
		}
	}
	if len(problems) > 0 {
		return Upstream{}, fmt.Errorf("%w: integration %s: %s", integrations.ErrInvalid, r.Key, strings.Join(problems, "; "))
	}
	u.adminPassword = r.Secrets["admin_password"]
	if u.adminPassword == "" {
		return Upstream{}, fmt.Errorf("%w: integration %s: secret admin_password is not set", integrations.ErrNotConfigured, r.Key)
	}
	return u, nil
}

func portValue(v any) (int, error) {
	var p float64
	switch x := v.(type) {
	case nil:
		return 5432, nil
	case float64:
		p = x
	case int:
		p = float64(x)
	case int64:
		p = float64(x)
	case json.Number:
		f, err := x.Float64()
		if err != nil {
			return 0, errors.New("port must be a number")
		}
		p = f
	case string:
		if strings.TrimSpace(x) == "" {
			return 5432, nil
		}
		n, err := strconv.Atoi(strings.TrimSpace(x))
		if err != nil {
			return 0, errors.New("port must be a number")
		}
		p = float64(n)
	default:
		return 0, errors.New("port must be a number")
	}
	if p != math.Trunc(p) || p < 1 || p > 65535 {
		return 0, errors.New("port must be an integer in 1..65535")
	}
	return int(p), nil
}

// UpstreamConfig describes the upstream in the Phase 1 shape pgproxy uses for
// policy targets and cancel requests, connecting as user. PasswordSecret is
// always empty: integration-backed upstreams never read passwords from YAML
// secrets.
func (u Upstream) UpstreamConfig(user string) config.UpstreamConfig {
	return config.UpstreamConfig{Host: u.Host, Port: u.Port, Database: u.Database, User: user,
		SSLMode: u.SSLMode, Environment: u.Environment}
}

// AdminConnConfig returns a pgconn config that logs in as the integration's
// admin user (used for role management, undo and snapshot verification).
func (u Upstream) AdminConnConfig(runtime map[string]string) (*pgconn.Config, error) {
	return BuildConnConfig(u.Host, u.Port, u.Database, u.AdminUser, u.adminPassword, u.SSLMode, runtime)
}

// BuildConnConfig builds a pgconn config from discrete settings without
// consulting PG* environment variables for the password. Shared by pgproxy
// (legacy upstreams), pgundo and this package.
func BuildConnConfig(host string, port int, database, user, password, sslmode string, runtime map[string]string) (*pgconn.Config, error) {
	if port == 0 {
		port = 5432
	}
	if sslmode == "" {
		sslmode = "prefer"
	}
	kv := func(k, v string) string {
		v = strings.ReplaceAll(v, `\`, `\\`)
		v = strings.ReplaceAll(v, `'`, `\'`)
		return k + "='" + v + "'"
	}
	dsn := strings.Join([]string{
		kv("host", host), kv("port", strconv.Itoa(port)), kv("dbname", database),
		kv("user", user), kv("sslmode", sslmode),
	}, " ")
	cfg, err := pgconn.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse upstream config: %w", err)
	}
	cfg.Password = password
	if cfg.RuntimeParams == nil {
		cfg.RuntimeParams = map[string]string{}
	}
	for k, v := range runtime {
		cfg.RuntimeParams[k] = v
	}
	cfg.ConnectTimeout = connectTimeout
	return cfg, nil
}

// rowSource is implemented by sources (integrations.PGStore) that can tell
// whether an integration row exists, independent of its status and secrets.
type rowSource interface {
	GetIntegration(ctx context.Context, key string) (integrations.Integration, error)
}

// Resolve fetches and validates the postgres:<name> integration. It returns
// ErrUpstreamNotManaged when no such integration exists.
func Resolve(ctx context.Context, src integrations.Source, upstream string) (Upstream, error) {
	if src == nil {
		return Upstream{}, ErrUpstreamNotManaged
	}
	name, err := NameFromKey(upstream)
	if err != nil {
		// Not a valid integration name: it cannot be an integration.
		return Upstream{}, ErrUpstreamNotManaged
	}
	r, err := src.Get(ctx, Key(name))
	if errors.Is(err, integrations.ErrNotConfigured) {
		// ErrNotConfigured covers both "no row" and "row exists but is
		// unconfigured or missing a secret". Only the first may fall back to a
		// YAML upstream; a broken integration must fail closed rather than
		// hand agents the shared static user.
		rs, ok := src.(rowSource)
		if !ok {
			return Upstream{}, ErrUpstreamNotManaged
		}
		_, gerr := rs.GetIntegration(ctx, Key(name))
		switch {
		case errors.Is(gerr, integrations.ErrNotConfigured):
			return Upstream{}, ErrUpstreamNotManaged
		case gerr != nil:
			return Upstream{}, fmt.Errorf("resolve integration %s: %w", Key(name), gerr)
		default:
			return Upstream{}, fmt.Errorf("resolve integration %s: integration exists but is not usable: %w", Key(name), err)
		}
	}
	if err != nil {
		return Upstream{}, fmt.Errorf("resolve integration %s: %w", Key(name), err)
	}
	if r.Key == "" {
		r.Key = Key(name)
	}
	if r.Key != Key(name) {
		return Upstream{}, fmt.Errorf("%w: integration source returned %q for %q", integrations.ErrInvalid, r.Key, Key(name))
	}
	return ParseUpstream(r)
}

// ---- per-agent role names ----

const rolePrefix = "fortik_a_"

// maxIdent is Postgres' NAMEDATALEN-1.
const maxIdent = 63

// RoleName returns the per-agent login role for (agent, upstream):
// fortik_a_<sanitized agent>_<6 hex>. The hash covers the upstream name and the
// agent id, so two upstreams on one cluster (roles are cluster-wide) never
// share a role and its memberships, and two agents whose ids sanitize alike
// get different roles. The result is at most 63 bytes.
func RoleName(agentID, upstream string) string {
	sum := sha256.Sum256([]byte(upstream + "\x00" + agentID))
	suffix := "_" + hex.EncodeToString(sum[:3])
	var b strings.Builder
	for _, r := range strings.ToLower(agentID) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	s := b.String()
	if max := maxIdent - len(rolePrefix) - len(suffix); len(s) > max {
		s = s[:max]
	}
	return rolePrefix + s + suffix
}

// roleComment marks a role as Fortik-managed for exactly one (agent,
// upstream). A role with the right name but another comment is never reused.
func roleComment(agentID, upstream string) string {
	return "fortik-managed agent role; agent=" + agentID + "; upstream=" + upstream
}
