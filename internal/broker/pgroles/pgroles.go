// Package pgroles gives every agent its own login role on each
// integration-backed Postgres upstream (postgres:<name>). The role is a member
// of exactly one of the integration's read_role / write_role, chosen by the
// agent's postgres access profile, so the database's own privilege system is
// a second wall behind Fortik's per-statement decisions. Each client session
// gets a fresh random password that expires after the configured TTL; the
// password never leaves the process (pgproxy logs in with it) and is never
// logged, stored or recorded.
package pgroles

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"fortik/internal/access"
	"fortik/internal/action"
	"fortik/internal/broker"
	"fortik/internal/control"
	"fortik/internal/integrations"
	"fortik/internal/pgsql"
)

// Access modes of a postgres access profile (docs/PHASE2_DESIGN.md §5).
const (
	ModeNone      = "none"
	ModeReadOnly  = "read_only"
	ModeReadWrite = "read_write"
)

var (
	// ErrNoAccess: the agent's postgres profile is missing, or the upstream is
	// absent from it or set to none (or to an unknown mode).
	ErrNoAccess = errors.New("no postgres access for this agent on this upstream (access profile)")
	// ErrAgentBlocked: the agent is unregistered, quarantined or killed.
	ErrAgentBlocked = errors.New("agent may not receive credentials at its control level")
	// ErrRoleConflict: a role with the managed name exists but is not the
	// Fortik-managed role for this (agent, upstream), or has attributes or
	// memberships Fortik does not grant. It is never reused.
	ErrRoleConflict = errors.New("upstream role conflict")
)

// Recorder stores an in-process issuance (credential_issuances + Diary
// credential.issued). broker.Broker satisfies it.
type Recorder interface {
	RecordIssuance(ctx context.Context, c broker.Credential, agentID, instanceID string) error
}

// Profiles returns the agent's current access profile. access.Store satisfies it.
type Profiles interface {
	Current(ctx context.Context, agentID, system string) (access.Profile, error)
}

// Levels returns the agent's control state. *control.Store satisfies it.
type Levels interface {
	Get(ctx context.Context, agentID string) (control.State, error)
}

// Config wires a Manager. Every field except TTL and Log is required.
type Config struct {
	Integrations integrations.Source
	Access       Profiles
	Control      Levels
	Recorder     Recorder
	// TTL is config.BrokerConfig.PostgresSessionTTL (default 15m): how long
	// an issued password can be used to log in.
	TTL time.Duration
	Log *slog.Logger
}

// Manager issues and revokes per-agent upstream roles. It implements
// broker.Adapter (System "postgres") and integrations.Tester ("postgres").
type Manager struct {
	src    integrations.Source
	access Profiles
	levels Levels
	rec    Recorder
	ttl    time.Duration
	log    *slog.Logger

	mu    sync.Mutex
	locks map[string]chan struct{} // per (agent, upstream)
}

var (
	_ broker.Adapter      = (*Manager)(nil)
	_ integrations.Tester = (*Manager)(nil)
)

// New validates cfg and returns a Manager.
func New(cfg Config) (*Manager, error) {
	if cfg.Integrations == nil || cfg.Access == nil || cfg.Control == nil || cfg.Recorder == nil {
		return nil, errors.New("pgroles: integrations source, access profiles, control store and issuance recorder are required")
	}
	if cfg.TTL < 0 {
		return nil, errors.New("pgroles: TTL must not be negative")
	}
	if cfg.TTL == 0 {
		cfg.TTL = 15 * time.Minute
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Manager{
		src: cfg.Integrations, access: cfg.Access, levels: cfg.Control, rec: cfg.Recorder,
		ttl: cfg.TTL, log: cfg.Log.With("component", "pgroles"), locks: map[string]chan struct{}{},
	}, nil
}

// System implements broker.Adapter and integrations.Tester.
func (m *Manager) System() string { return System }

// Mint implements broker.Adapter. Postgres credentials are only used inside
// pgproxy and are never handed to an agent.
func (m *Manager) Mint(context.Context, string, map[string]any, time.Duration) (broker.Credential, error) {
	return broker.Credential{}, broker.ErrUnsupported
}

// Session is one issued per-agent login. Password is for in-process use only.
type Session struct {
	IssuanceID string
	User       string // the per-agent role
	Password   string
	ExpiresAt  time.Time // the role's VALID UNTIL (database clock)
	Mode       string    // read_only | read_write
	Upstream   Upstream
}

func (s Session) String() string {
	return fmt.Sprintf("pgroles.Session{%s role=%s mode=%s expires=%s}", s.Upstream.Name, s.User, s.Mode, s.ExpiresAt.Format(time.RFC3339))
}

// GoString keeps %#v from printing the password.
func (s Session) GoString() string { return s.String() }

// LogValue keeps slog from printing the password.
func (s Session) LogValue() slog.Value {
	return slog.GroupValue(slog.String("upstream", s.Upstream.Name), slog.String("role", s.User),
		slog.String("mode", s.Mode), slog.Time("expires_at", s.ExpiresAt), slog.String("issuance_id", s.IssuanceID))
}

// Session ensures the agent's role on upstream ("acme_prod" or
// "postgres:acme_prod") and sets a new password. The previous password of the
// role stops working at once; this one stops working at ExpiresAt. Use
// Connect to log in atomically (no concurrent rotation in between).
// Errors: ErrUpstreamNotManaged (no integration), ErrNoAccess, ErrAgentBlocked,
// ErrRoleConflict, or a wrapped connection / database error.
func (m *Manager) Session(ctx context.Context, agentID, instanceID, upstream string) (Session, error) {
	s, release, err := m.issue(ctx, agentID, instanceID, upstream)
	if err != nil {
		return Session{}, err
	}
	release()
	return s, nil
}

// Connect issues a Session and logs in to the upstream with it while still
// holding the role's locks, so a concurrent session for the same (agent,
// upstream) cannot rotate the password between issuance and login. runtime
// holds startup parameters (application_name, client_encoding, ...).
func (m *Manager) Connect(ctx context.Context, agentID, instanceID, upstream string, runtime map[string]string) (*pgconn.PgConn, Session, error) {
	s, release, err := m.issue(ctx, agentID, instanceID, upstream)
	if err != nil {
		return nil, Session{}, err
	}
	defer release()
	u := s.Upstream
	cfg, err := BuildConnConfig(u.Host, u.Port, u.Database, s.User, s.Password, u.SSLMode, runtime)
	if err != nil {
		return nil, Session{}, err
	}
	cctx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	pc, err := pgconn.ConnectConfig(cctx, cfg)
	if err != nil {
		return nil, Session{}, fmt.Errorf("log in to upstream %s as %s: %w", u.Name, s.User, err)
	}
	return pc, s, nil
}

// AdminConnConfig resolves the upstream's integration and returns a config
// that logs in as its admin user. ErrUpstreamNotManaged when absent.
func (m *Manager) AdminConnConfig(ctx context.Context, upstream string, runtime map[string]string) (*pgconn.Config, Upstream, error) {
	u, err := Resolve(ctx, m.src, upstream)
	if err != nil {
		return nil, Upstream{}, err
	}
	cfg, err := u.AdminConnConfig(runtime)
	return cfg, u, err
}

// agentPattern mirrors action.Action's id validation.
var agentPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$`)

// issue runs the whole issuance and returns a release func that must be
// called once the caller is done with the password (it frees the locks).
func (m *Manager) issue(ctx context.Context, agentID, instanceID, upstream string) (Session, func(), error) {
	if !agentPattern.MatchString(agentID) {
		return Session{}, nil, fmt.Errorf("%w: invalid agent id", ErrNoAccess)
	}
	name, err := NameFromKey(upstream)
	if err != nil {
		return Session{}, nil, ErrUpstreamNotManaged
	}
	u, err := Resolve(ctx, m.src, name)
	if err != nil {
		return Session{}, nil, err
	}
	// Cheap checks before touching the upstream; repeated under the locks.
	if err := m.checkLevel(ctx, agentID); err != nil {
		return Session{}, nil, err
	}
	if _, err := m.mode(ctx, agentID, name); err != nil {
		return Session{}, nil, err
	}

	unlock, err := m.lock(ctx, agentID+"\x00"+name)
	if err != nil {
		return Session{}, nil, err
	}
	role := RoleName(agentID, name)
	conn, err := adminConnect(ctx, u, "fortik:pgroles:issue")
	if err != nil {
		unlock()
		return Session{}, nil, err
	}
	release := func() {
		// Closing the admin connection also frees the advisory lock.
		_ = conn.Close(context.Background())
		unlock()
	}
	fail := func(err error) (Session, func(), error) {
		release()
		return Session{}, nil, err
	}
	// The advisory lock serializes issuance and revocation across Fortik
	// processes sharing the upstream; it is held until release.
	if _, err := conn.Exec(ctx, "SELECT pg_catalog.pg_advisory_lock(pg_catalog.hashtextextended($1, 0))", lockKey(role)); err != nil {
		return fail(fmt.Errorf("lock role %s on upstream %s: %w", role, name, err))
	}
	// Re-check under the lock: a step-down to QUARANTINED/KILLED (followed by
	// RevokeAgent) or a narrowed profile must not race with this issuance.
	if err := m.checkLevel(ctx, agentID); err != nil {
		return fail(err)
	}
	mode, err := m.mode(ctx, agentID, name)
	if err != nil {
		return fail(err)
	}

	password, err := newPassword()
	if err != nil {
		return fail(err)
	}
	verifier, err := scramVerifier(password)
	if err != nil {
		return fail(err)
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return fail(fmt.Errorf("upstream %s: begin: %w", name, err))
	}
	defer tx.Rollback(context.WithoutCancel(ctx)) //nolint:errcheck // no-op after commit
	expires, err := m.ensureRole(ctx, tx, u, agentID, role, mode, verifier)
	if err != nil {
		return fail(err)
	}
	cred := broker.Credential{
		IssuanceID: action.NewID("iss"),
		System:     System,
		ExpiresAt:  expires,
		Scope:      map[string]any{"upstream": name, "mode": mode, "role": role},
	}
	// Recorded before the role change commits: a credential that works is
	// always on record. If the commit then fails, the record names a
	// password that never became valid (logged below).
	if err := m.rec.RecordIssuance(ctx, cred, agentID, instanceID); err != nil {
		return fail(fmt.Errorf("record postgres issuance: %w", err))
	}
	if err := tx.Commit(ctx); err != nil {
		m.log.Error("role change failed to commit after the issuance was recorded",
			"issuance_id", cred.IssuanceID, "agent_id", agentID, "upstream", name, "err", err)
		return fail(fmt.Errorf("upstream %s: commit role change: %w", name, err))
	}
	m.log.Info("postgres session credential issued", "agent_id", agentID, "instance_id", instanceID,
		"upstream", name, "role", role, "mode", mode, "expires_at", expires, "issuance_id", cred.IssuanceID)
	return Session{IssuanceID: cred.IssuanceID, User: role, Password: password, ExpiresAt: expires,
		Mode: mode, Upstream: u}, release, nil
}

func lockKey(role string) string { return "fortik:pgroles:" + role }

// checkLevel refuses unregistered, quarantined and killed agents.
func (m *Manager) checkLevel(ctx context.Context, agentID string) error {
	st, err := m.levels.Get(ctx, agentID)
	if err != nil {
		return fmt.Errorf("control state: %w", err)
	}
	if !st.Registered {
		return fmt.Errorf("%w: agent is not registered", ErrAgentBlocked)
	}
	if !st.Level.Valid() || st.Level >= control.Quarantined {
		return fmt.Errorf("%w: agent is %s", ErrAgentBlocked, st.Level)
	}
	return nil
}

// postgresProfile is the postgres access profile shape (§5).
type postgresProfile struct {
	Upstreams map[string]string `json:"upstreams"`
}

// mode returns read_only or read_write for (agent, upstream), else ErrNoAccess.
func (m *Manager) mode(ctx context.Context, agentID, upstream string) (string, error) {
	p, err := m.access.Current(ctx, agentID, System)
	if errors.Is(err, access.ErrNotFound) {
		return "", fmt.Errorf("%w: agent has no postgres access profile", ErrNoAccess)
	}
	if err != nil {
		return "", fmt.Errorf("access profile: %w", err)
	}
	if p.System != "" && p.System != System {
		return "", fmt.Errorf("%w: profile is for system %q", ErrNoAccess, p.System)
	}
	var pp postgresProfile
	if err := json.Unmarshal(p.Profile, &pp); err != nil {
		return "", fmt.Errorf("%w: postgres access profile is not valid JSON", ErrNoAccess)
	}
	switch mode := pp.Upstreams[upstream]; mode {
	case ModeReadOnly, ModeReadWrite:
		return mode, nil
	case "", ModeNone:
		return "", fmt.Errorf("%w: upstream %q is %s in the profile", ErrNoAccess, upstream, orNone(mode))
	default:
		return "", fmt.Errorf("%w: unknown mode %q for upstream %q", ErrNoAccess, mode, upstream)
	}
}

func orNone(mode string) string {
	if mode == "" {
		return "absent"
	}
	return mode
}

// lock takes the in-process per-(agent, upstream) lock, honouring ctx.
func (m *Manager) lock(ctx context.Context, key string) (func(), error) {
	m.mu.Lock()
	ch, ok := m.locks[key]
	if !ok {
		ch = make(chan struct{}, 1)
		m.locks[key] = ch
	}
	m.mu.Unlock()
	select {
	case ch <- struct{}{}:
		return func() { <-ch }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func adminConnect(ctx context.Context, u Upstream, app string) (*pgx.Conn, error) {
	pc, err := u.AdminConnConfig(map[string]string{"application_name": app})
	if err != nil {
		return nil, err
	}
	cc, err := pgx.ParseConfig("")
	if err != nil {
		return nil, err
	}
	cc.Config = *pc
	cctx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	conn, err := pgx.ConnectConfig(cctx, cc)
	if err != nil {
		return nil, fmt.Errorf("connect to upstream %s as admin: %w", u.Name, err)
	}
	return conn, nil
}

type roleRow struct {
	oid                                       uint32
	super, createRole, createDB, repl, bypass bool
	comment                                   *string
}

func lookupRole(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, role string) (*roleRow, error) {
	var r roleRow
	err := q.QueryRow(ctx, `SELECT oid, rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls,
       pg_catalog.shobj_description(oid, 'pg_authid')
FROM pg_catalog.pg_roles WHERE rolname = $1`, role).
		Scan(&r.oid, &r.super, &r.createRole, &r.createDB, &r.repl, &r.bypass, &r.comment)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// ensureRole creates or updates the role inside tx: LOGIN, INHERIT, the new
// password verifier, VALID UNTIL now()+ttl, and membership in exactly the
// role the mode allows. It returns the expiry (database clock).
func (m *Manager) ensureRole(ctx context.Context, tx pgx.Tx, u Upstream, agentID, role, mode, verifier string) (time.Time, error) {
	target, other := u.ReadRole, u.WriteRole
	if mode == ModeReadWrite {
		target, other = u.WriteRole, u.ReadRole
	}
	var serverVersion int
	var expires time.Time
	if err := tx.QueryRow(ctx, `SELECT pg_catalog.current_setting('server_version_num')::int,
       pg_catalog.now() + pg_catalog.make_interval(secs => $1)`, m.ttl.Seconds()).Scan(&serverVersion, &expires); err != nil {
		return time.Time{}, fmt.Errorf("upstream %s: %w", u.Name, err)
	}
	var targetOID, otherOID uint32
	for _, x := range []struct {
		name string
		oid  *uint32
	}{{target, &targetOID}, {other, &otherOID}} {
		err := tx.QueryRow(ctx, `SELECT oid FROM pg_catalog.pg_roles WHERE rolname = $1`, x.name).Scan(x.oid)
		if errors.Is(err, pgx.ErrNoRows) {
			return time.Time{}, fmt.Errorf("%w: upstream %s: role %q does not exist", integrations.ErrInvalid, u.Name, x.name)
		}
		if err != nil {
			return time.Time{}, fmt.Errorf("upstream %s: %w", u.Name, err)
		}
	}
	if mode == ModeReadOnly {
		// read_role must not carry write_role's privileges.
		var leaks bool
		if err := tx.QueryRow(ctx, `SELECT pg_catalog.pg_has_role($1::oid, $2::oid, 'MEMBER')`, targetOID, otherOID).Scan(&leaks); err != nil {
			return time.Time{}, fmt.Errorf("upstream %s: %w", u.Name, err)
		}
		if leaks {
			return time.Time{}, fmt.Errorf("%w: upstream %s: read_role %q is a member of write_role %q", integrations.ErrInvalid, u.Name, u.ReadRole, u.WriteRole)
		}
	}

	qrole := pgsql.QuoteIdent(role)
	validUntil := pgsql.QuoteLiteral(expires.UTC().Format("2006-01-02 15:04:05.999999+00"))
	comment := roleComment(agentID, u.Name)
	existing, err := lookupRole(ctx, tx, role)
	if err != nil {
		return time.Time{}, fmt.Errorf("upstream %s: %w", u.Name, err)
	}
	if existing == nil {
		// Defaults: NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS.
		if _, err := tx.Exec(ctx, "CREATE ROLE "+qrole+" WITH LOGIN INHERIT PASSWORD "+pgsql.QuoteLiteral(verifier)+" VALID UNTIL "+validUntil); err != nil {
			return time.Time{}, fmt.Errorf("upstream %s: create role %s: %w", u.Name, role, err)
		}
		if _, err := tx.Exec(ctx, "COMMENT ON ROLE "+qrole+" IS "+pgsql.QuoteLiteral(comment)); err != nil {
			return time.Time{}, fmt.Errorf("upstream %s: comment on role %s: %w", u.Name, role, err)
		}
		if serverVersion >= 160000 {
			// Fortik's admin may SET ROLE to the agent's role (never inherit its
			// privileges) so an approved safe form or an undo can rename tables
			// the agent created. The agent gains nothing from this.
			if _, err := tx.Exec(ctx, "GRANT "+qrole+" TO CURRENT_USER WITH INHERIT FALSE, SET TRUE"); err != nil {
				return time.Time{}, fmt.Errorf("upstream %s: grant set on %s to admin: %w", u.Name, role, err)
			}
		}
	} else {
		if existing.comment == nil || *existing.comment != comment {
			return time.Time{}, fmt.Errorf("%w: upstream %s: role %s exists but is not Fortik's role for this agent", ErrRoleConflict, u.Name, role)
		}
		if _, err := tx.Exec(ctx, "ALTER ROLE "+qrole+" WITH LOGIN INHERIT PASSWORD "+pgsql.QuoteLiteral(verifier)+" VALID UNTIL "+validUntil); err != nil {
			return time.Time{}, fmt.Errorf("upstream %s: alter role %s: %w", u.Name, role, err)
		}
		if serverVersion >= 160000 {
			if _, err := tx.Exec(ctx, "GRANT "+qrole+" TO CURRENT_USER WITH INHERIT FALSE, SET TRUE"); err != nil {
				return time.Time{}, fmt.Errorf("upstream %s: grant set on %s to admin: %w", u.Name, role, err)
			}
		}
	}
	r, err := lookupRole(ctx, tx, role)
	if err != nil || r == nil {
		return time.Time{}, fmt.Errorf("upstream %s: role %s not found after update: %v", u.Name, role, err)
	}
	if r.super || r.createRole || r.createDB || r.repl || r.bypass {
		return time.Time{}, fmt.Errorf("%w: upstream %s: role %s has SUPERUSER/CREATEROLE/CREATEDB/REPLICATION/BYPASSRLS", ErrRoleConflict, u.Name, role)
	}

	members, err := memberships(ctx, tx, r.oid, serverVersion)
	if err != nil {
		return time.Time{}, fmt.Errorf("upstream %s: %w", u.Name, err)
	}
	if _, ok := members[other]; ok {
		if _, err := tx.Exec(ctx, "REVOKE "+pgsql.QuoteIdent(other)+" FROM "+qrole); err != nil {
			return time.Time{}, fmt.Errorf("upstream %s: revoke %s from %s: %w", u.Name, other, role, err)
		}
	}
	grant := "GRANT " + pgsql.QuoteIdent(target) + " TO " + qrole
	if serverVersion >= 160000 {
		// Privileges must apply (INHERIT), and the agent cannot SET ROLE to
		// the group role (objects it creates stay its own).
		grant += " WITH INHERIT TRUE, SET FALSE"
	}
	if inherit, ok := members[target]; !ok || !inherit || serverVersion >= 160000 {
		if _, err := tx.Exec(ctx, grant); err != nil {
			return time.Time{}, fmt.Errorf("upstream %s: grant %s to %s: %w", u.Name, target, role, err)
		}
	}
	members, err = memberships(ctx, tx, r.oid, serverVersion)
	if err != nil {
		return time.Time{}, fmt.Errorf("upstream %s: %w", u.Name, err)
	}
	var extra []string
	for name := range members {
		if name != target {
			extra = append(extra, name)
		}
	}
	sort.Strings(extra)
	if len(extra) > 0 {
		return time.Time{}, fmt.Errorf("%w: upstream %s: role %s is also a member of %s (granted outside Fortik?)",
			ErrRoleConflict, u.Name, role, strings.Join(extra, ", "))
	}
	if inherit, ok := members[target]; !ok || !inherit {
		return time.Time{}, fmt.Errorf("%w: upstream %s: role %s does not inherit %s", ErrRoleConflict, u.Name, role, target)
	}
	return expires, nil
}

// memberships returns the roles member belongs to directly, with whether at
// least one grant of each is inheritable.
func memberships(ctx context.Context, tx pgx.Tx, member uint32, serverVersion int) (map[string]bool, error) {
	inherit := "true"
	if serverVersion >= 160000 {
		inherit = "m.inherit_option"
	}
	rows, err := tx.Query(ctx, `SELECT r.rolname, bool_or(`+inherit+`)
FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid = m.roleid
WHERE m.member = $1 GROUP BY r.rolname`, member)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var name string
		var inh bool
		if err := rows.Scan(&name, &inh); err != nil {
			return nil, err
		}
		out[name] = inh
	}
	return out, rows.Err()
}

// RevokeAgent implements broker.Adapter. For every integration-backed
// upstream it sets the agent's role NOLOGIN, clears its password and
// terminates the role's live backends. It returns what was actually achieved
// per upstream; new sessions are refused afterwards because issuance checks
// the control level (QUARANTINED/KILLED) under the same lock.
func (m *Manager) RevokeAgent(ctx context.Context, agentID string) (string, error) {
	list, err := m.src.List(ctx, System)
	if err != nil {
		return "postgres: revocation not attempted: integrations unavailable", fmt.Errorf("list postgres integrations: %w", err)
	}
	// Integrations whose admin secret is missing cannot be reached: report
	// them as NOT revoked rather than skipping them silently.
	var parts []string
	var errs []error
	if bl, ok := m.src.(integrations.BrokenLister); ok {
		broken, err := bl.Broken(ctx, System)
		if err != nil {
			parts = append(parts, "postgres: could not check for integrations with missing secrets")
			errs = append(errs, err)
		}
		for _, k := range broken {
			parts = append(parts, k+": NOT revoked (the integration's admin secret is missing from the secret store)")
			errs = append(errs, fmt.Errorf("%s: admin secret missing: agent role not revoked", k))
		}
	}
	if len(list) == 0 && len(parts) == 0 {
		return "postgres: no integration-backed upstreams; nothing revoked (legacy YAML upstreams use a shared static user that cannot be revoked per agent)", nil
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Key < list[j].Key })
	for _, r := range list {
		desc, err := m.revokeOne(ctx, agentID, r)
		parts = append(parts, desc)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return strings.Join(parts, "; "), errors.Join(errs...)
}

func (m *Manager) revokeOne(ctx context.Context, agentID string, r integrations.Resolved) (string, error) {
	u, err := ParseUpstream(r)
	if err != nil {
		return r.Key + ": NOT revoked (integration invalid)", err
	}
	role := RoleName(agentID, u.Name)
	prefix := Key(u.Name) + ": role " + role
	unlock, err := m.lock(ctx, agentID+"\x00"+u.Name)
	if err != nil {
		return prefix + ": NOT revoked", err
	}
	defer unlock()
	conn, err := adminConnect(ctx, u, "fortik:pgroles:revoke")
	if err != nil {
		return prefix + ": NOT revoked (upstream unreachable)", err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	if _, err := conn.Exec(ctx, "SELECT pg_catalog.pg_advisory_lock(pg_catalog.hashtextextended($1, 0))", lockKey(role)); err != nil {
		return prefix + ": NOT revoked", fmt.Errorf("%s: lock: %w", u.Name, err)
	}
	existing, err := lookupRole(ctx, conn, role)
	if err != nil {
		return prefix + ": NOT revoked", fmt.Errorf("%s: %w", u.Name, err)
	}
	if existing == nil {
		return prefix + ": no role (never issued); nothing to revoke", nil
	}
	if existing.comment == nil || *existing.comment != roleComment(agentID, u.Name) {
		return prefix + ": NOT revoked (role exists but is not Fortik-managed for this agent)",
			fmt.Errorf("%w: %s: role %s is not Fortik-managed for agent", ErrRoleConflict, u.Name, role)
	}
	qrole := pgsql.QuoteIdent(role)
	if _, err := conn.Exec(ctx, "ALTER ROLE "+qrole+" WITH NOLOGIN PASSWORD NULL"); err != nil {
		return prefix + ": NOT revoked (ALTER ROLE failed)", fmt.Errorf("%s: alter role: %w", u.Name, err)
	}
	var live, killed int64
	err = conn.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE pg_catalog.pg_terminate_backend(pid))
FROM pg_catalog.pg_stat_activity WHERE usename = $1 AND pid <> pg_catalog.pg_backend_pid()`, role).Scan(&live, &killed)
	if err != nil {
		return prefix + ": NOLOGIN set and password cleared; live sessions NOT terminated (" + sanitize(err) + ")",
			fmt.Errorf("%s: terminate sessions: %w", u.Name, err)
	}
	desc := fmt.Sprintf("%s: NOLOGIN set, password cleared, %d of %d live sessions terminated", prefix, killed, live)
	m.log.Warn("postgres role revoked", "agent_id", agentID, "upstream", u.Name, "role", role,
		"sessions_live", live, "sessions_terminated", killed)
	if killed < live {
		return desc, fmt.Errorf("%s: %d of %d sessions of %s could not be terminated", u.Name, live-killed, live, role)
	}
	return desc, nil
}

// sanitize returns a short, secret-free description of a database error.
func sanitize(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code + ": " + pe.Message
	}
	msg := err.Error()
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return msg
}
