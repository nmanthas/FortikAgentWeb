// Package discoverers holds the shadow-agent discoverers (and revokers) for
// the systems Fortik brokers: Postgres upstreams, GitHub, AWS IAM and
// Google Workspace. Each reads the integration configured in the console,
// lists standing credentials (identifiers only, never secrets), flags those
// used by software, and can revoke a credential when security asks and
// Fortik really can. An unconfigured system is reported as not scanned.
package discoverers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"fortik/internal/broker/pgroles"
	"fortik/internal/integrations"
	"fortik/internal/pgsql"
	"fortik/internal/shadow"
)

// Postgres discovers non-Fortik LOGIN roles on every postgres:* upstream.
type Postgres struct {
	src integrations.Source
	// exclude are extra roles never reported (e.g. Fortik's own database
	// user and YAML upstream users on the same cluster).
	exclude map[string]bool
	log     *slog.Logger
}

// NewPostgres returns the Postgres discoverer and revoker.
func NewPostgres(src integrations.Source, excludeRoles []string, log *slog.Logger) *Postgres {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	ex := map[string]bool{}
	for _, r := range excludeRoles {
		if r = strings.TrimSpace(r); r != "" {
			ex[r] = true
		}
	}
	return &Postgres{src: src, exclude: ex, log: log.With("component", "shadow-postgres")}
}

func (p *Postgres) System() string { return shadow.SystemPostgres }

// maxRoles bounds one upstream's listing.
const maxRoles = 5000

// interactiveApps are application_name prefixes of tools a person drives.
var interactiveApps = []string{
	"psql", "pgadmin", "dbeaver", "datagrip", "tableplus", "postico", "navicat", "heidisql", "beekeeper",
	"azure data studio", "azuredatastudio", "dbvisualizer", "sql workbench", "sqlworkbench", "pgcli", "valentina",
	"toad", "intellij", "pycharm", "goland", "rubymine", "webstorm", "dbgate", "jetbrains", "pgweb", "omnidb",
	"adminer", "phppgadmin", "pgmodeler", "sqlectron", "arctype", "jupyter-sql-interactive",
}

func interactiveApp(app string) bool {
	a := strings.ToLower(strings.TrimSpace(app))
	if a == "" {
		return false
	}
	for _, p := range interactiveApps {
		if strings.HasPrefix(a, p) {
			return true
		}
	}
	return false
}

func connectAdmin(ctx context.Context, u pgroles.Upstream, app string) (*pgx.Conn, error) {
	pc, err := u.AdminConnConfig(map[string]string{"application_name": app})
	if err != nil {
		return nil, err
	}
	cc, err := pgx.ParseConfig("")
	if err != nil {
		return nil, err
	}
	cc.Config = *pc
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := pgx.ConnectConfig(cctx, cc)
	if err != nil {
		return nil, fmt.Errorf("connect to upstream %s as its admin role: %s", u.Name, pgErr(err))
	}
	return conn, nil
}

// pgErr returns a short, secret-free description of a database error.
func pgErr(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code + ": " + pe.Message
	}
	var ce *pgconn.ConnectError
	if errors.As(err, &ce) {
		return "connection failed"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timed out"
	}
	return shadow.Clean(err.Error(), 200)
}

// systemRoles collects every role Fortik itself configured on any
// integration (admin, read and write roles, memory admins) plus the extra
// exclusions.
func (p *Postgres) systemRoles(ctx context.Context, list []integrations.Resolved) map[string]bool {
	out := map[string]bool{}
	for k := range p.exclude {
		out[k] = true
	}
	for _, r := range list {
		for _, k := range []string{"admin_user", "read_role", "write_role"} {
			if v := strings.TrimSpace(r.Text(k)); v != "" {
				out[v] = true
			}
		}
	}
	if mem, err := p.src.List(ctx, integrations.SystemMemory); err == nil {
		for _, r := range mem {
			if v := strings.TrimSpace(r.Text("admin_user")); v != "" {
				out[v] = true
			}
		}
	}
	return out
}

// Discover implements shadow.Discoverer.
func (p *Postgres) Discover(ctx context.Context) []shadow.ScanResult {
	if p.src == nil {
		return []shadow.ScanResult{{System: shadow.SystemPostgres, Status: shadow.ScanNotConfigured, Detail: "no integrations source: not scanned"}}
	}
	list, err := p.src.List(ctx, pgroles.System)
	if err != nil {
		return []shadow.ScanResult{{System: shadow.SystemPostgres, Status: shadow.ScanError, Detail: "could not list postgres integrations: not scanned"}}
	}
	var out []shadow.ScanResult
	if bl, ok := p.src.(integrations.BrokenLister); ok {
		broken, err := bl.Broken(ctx, pgroles.System)
		if err != nil {
			out = append(out, shadow.ScanResult{System: shadow.SystemPostgres, Status: shadow.ScanError,
				Detail: "could not check postgres integrations for missing secrets"})
		}
		for _, k := range broken {
			out = append(out, shadow.ScanResult{System: shadow.SystemPostgres, Integration: k, Status: shadow.ScanError,
				Detail: "the integration's admin secret is missing from the secret store: not scanned"})
		}
	}
	if len(list) == 0 && len(out) == 0 {
		return []shadow.ScanResult{{System: shadow.SystemPostgres, Status: shadow.ScanNotConfigured,
			Detail: "no postgres:* integration is configured: not scanned"}}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Key < list[j].Key })
	sys := p.systemRoles(ctx, list)
	for _, r := range list {
		out = append(out, p.scanOne(ctx, r, sys))
	}
	return out
}

type roleInfo struct {
	name                                  string
	super, createRole, createDB, repl, by bool
	validUntil                            *time.Time
	connLimit                             int32
	comment                               *string
}

type sessionInfo struct {
	app, addr, hostname, db string
}

func (p *Postgres) scanOne(ctx context.Context, r integrations.Resolved, sys map[string]bool) shadow.ScanResult {
	res := shadow.ScanResult{System: shadow.SystemPostgres, Integration: r.Key}
	u, err := pgroles.ParseUpstream(r)
	if err != nil {
		res.Status, res.Detail = shadow.ScanError, "integration settings are invalid: not scanned"
		return res
	}
	conn, err := connectAdmin(ctx, u, "fortik:shadow:scan")
	if err != nil {
		res.Status, res.Detail = shadow.ScanError, err.Error()+": not scanned"
		return res
	}
	defer conn.Close(context.WithoutCancel(ctx))

	rows, err := conn.Query(ctx, `SELECT r.rolname, r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolreplication, r.rolbypassrls,
		r.rolvaliduntil, r.rolconnlimit, pg_catalog.shobj_description(r.oid, 'pg_authid')
	FROM pg_catalog.pg_roles r
	WHERE r.rolcanlogin AND r.oid >= 16384 AND r.rolname !~ '^pg_'
	ORDER BY r.rolname LIMIT $1`, maxRoles+1)
	if err != nil {
		res.Status, res.Detail = shadow.ScanError, "list roles: "+pgErr(err)+": not scanned"
		return res
	}
	var roles []roleInfo
	var privileged []string
	for rows.Next() {
		var ri roleInfo
		if err := rows.Scan(&ri.name, &ri.super, &ri.createRole, &ri.createDB, &ri.repl, &ri.by, &ri.validUntil, &ri.connLimit, &ri.comment); err != nil {
			rows.Close()
			res.Status, res.Detail = shadow.ScanError, "list roles: "+pgErr(err)+": not scanned"
			return res
		}
		switch {
		case strings.HasPrefix(ri.name, "fortik_a_"), ri.comment != nil && strings.HasPrefix(*ri.comment, "fortik-managed"):
			continue // Fortik's own per-agent roles
		case sys[ri.name]:
			continue // the integration's admin/read/write roles and configured exclusions
		}
		// Superuser and replication login roles are the most dangerous
		// standing credentials: they are findings like any other role (the
		// bootstrap superuser is already excluded by oid). Revoking one is
		// manual: Fortik does not alter superusers.
		if ri.super || ri.repl {
			privileged = append(privileged, ri.name)
		}
		roles = append(roles, ri)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		res.Status, res.Detail = shadow.ScanError, "list roles: "+pgErr(err)+": not scanned"
		return res
	}
	truncated := false
	if len(roles) > maxRoles {
		roles, truncated = roles[:maxRoles], true
	}
	names := make([]string, len(roles))
	for i, ri := range roles {
		names[i] = ri.name
	}

	var hostsVisible bool
	if err := conn.QueryRow(ctx, `SELECT r.rolsuper OR pg_catalog.pg_has_role(current_user, 'pg_read_all_stats', 'USAGE')
		FROM pg_catalog.pg_roles r WHERE r.rolname = current_user`).Scan(&hostsVisible); err != nil {
		hostsVisible = false
	}
	sessions := map[string][]sessionInfo{}
	sessErr := ""
	if len(names) > 0 {
		srows, err := conn.Query(ctx, `SELECT usename, COALESCE(application_name, ''), COALESCE(pg_catalog.host(client_addr), ''),
			COALESCE(client_hostname, ''), COALESCE(datname, '')
		FROM pg_catalog.pg_stat_activity WHERE usename = ANY($1) AND pid <> pg_catalog.pg_backend_pid()`, names)
		if err != nil {
			sessErr = pgErr(err)
		} else {
			for srows.Next() {
				var user string
				var si sessionInfo
				if err := srows.Scan(&user, &si.app, &si.addr, &si.hostname, &si.db); err != nil {
					sessErr = pgErr(err)
					break
				}
				sessions[user] = append(sessions[user], si)
			}
			srows.Close()
			if err := srows.Err(); err != nil && sessErr == "" {
				sessErr = pgErr(err)
			}
		}
	}

	for _, ri := range roles {
		res.Credentials = append(res.Credentials, classifyRole(u, r.Key, ri, sessions[ri.name], hostsVisible))
	}
	res.Status = shadow.ScanScanned
	var notes []string
	notes = append(notes, fmt.Sprintf("%d non-Fortik login role(s) on %s/%s", len(roles), u.Host, u.Database))
	if len(privileged) > 0 {
		sort.Strings(privileged)
		notes = append(notes, fmt.Sprintf("%d superuser/replication login role(s) included (%s)", len(privileged),
			shadow.Clean(strings.Join(privileged, ", "), 300)))
	}
	if sessErr != "" {
		res.Status = shadow.ScanPartial
		notes = append(notes, "live sessions could not be read ("+sessErr+"): classified by role name only")
	}
	if !hostsVisible {
		notes = append(notes, "client hosts are not visible to the admin role (grant it pg_read_all_stats to see them)")
	}
	if truncated {
		res.Status = shadow.ScanPartial
		notes = append(notes, fmt.Sprintf("only the first %d roles were examined", maxRoles))
	}
	res.Detail = strings.Join(notes, "; ")
	return res
}

func classifyRole(u pgroles.Upstream, key string, ri roleInfo, sess []sessionInfo, hostsVisible bool) shadow.Credential {
	apps, hosts := map[string]bool{}, map[string]bool{}
	var softwareApps, interactive []string
	for _, s := range sess {
		app := shadow.Clean(s.app, 120)
		label := app
		if label == "" {
			label = "(none)"
		}
		if !apps[label] {
			apps[label] = true
			if interactiveApp(app) {
				interactive = append(interactive, label)
			} else {
				softwareApps = append(softwareApps, label)
			}
		}
		h := s.addr
		if s.hostname != "" {
			h = s.hostname
		}
		if h == "" && s.addr == "" && hostsVisible {
			h = "local socket"
		}
		if h != "" && len(hosts) < 10 {
			hosts[shadow.Clean(h, 128)] = true
		}
	}
	sort.Strings(softwareApps)
	sort.Strings(interactive)
	hint := shadow.SoftwareHint(ri.name)
	software, why := false, ""
	switch {
	case len(softwareApps) > 0:
		software = true
		why = "live sessions use non-interactive application_name " + strings.Join(limit(softwareApps, 5), ", ")
	case len(sess) == 0 && hint != "":
		software = true
		why = "no live session; the role name suggests automation (" + hint + ")"
	case len(interactive) > 0:
		why = "live sessions only from interactive tools (" + strings.Join(limit(interactive, 5), ", ") + ")"
	default:
		why = "no live session and no software indicator"
	}
	ev := map[string]any{
		"upstream": u.Name, "role": ri.name, "host": u.Host, "database": u.Database,
		"sessions_live":     len(sess),
		"application_names": limit(append(append([]string{}, softwareApps...), interactive...), 10),
		"attributes": map[string]any{"superuser": ri.super, "replication": ri.repl, "createrole": ri.createRole, "createdb": ri.createDB, "bypassrls": ri.by,
			"connection_limit": ri.connLimit, "password_expires": validUntil(ri.validUntil)},
		"classified_by": why,
	}
	if hint != "" {
		ev["name_hint"] = hint
	}
	if hostsVisible {
		hl := make([]string, 0, len(hosts))
		for h := range hosts {
			hl = append(hl, h)
		}
		sort.Strings(hl)
		ev["client_hosts"] = hl
	} else {
		ev["client_hosts_visible"] = false
	}
	label := "postgres role " + ri.name + " on " + u.Name
	switch {
	case ri.super:
		label += " (SUPERUSER)"
	case ri.repl:
		label += " (REPLICATION)"
	}
	return shadow.Credential{Kind: shadow.KindDBRole, Ref: u.Name + "/" + ri.name, Holder: ri.name, Software: software,
		Integration: key, Label: label, Evidence: ev}
}

func validUntil(t *time.Time) string {
	if t == nil || t.Year() > 9000 {
		return "never"
	}
	return t.UTC().Format(time.RFC3339)
}

func limit(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	if s == nil {
		return []string{}
	}
	return s
}

func evString(f shadow.Finding, key string) string {
	m := map[string]any{}
	_ = jsonUnmarshal(f.Evidence, &m)
	s, _ := m[key].(string)
	return s
}

// Revoke implements shadow.Revoker: ALTER ROLE ... NOLOGIN on the upstream
// and terminate the role's live sessions. Only both together count as
// revoked; the password is kept (NOLOGIN is reversible by a DBA).
func (p *Postgres) Revoke(ctx context.Context, f shadow.Finding) shadow.RevokeResult {
	notRevoked := func(detail string) shadow.RevokeResult {
		return shadow.RevokeResult{Outcome: shadow.OutcomeNotRevoked, Detail: detail}
	}
	if f.Kind != shadow.KindDBRole {
		return shadow.RevokeResult{Outcome: shadow.OutcomeManualRequired, Detail: "not a database role: revoke it in the postgres server"}
	}
	key, role, upstream := evString(f, "integration"), evString(f, "role"), evString(f, "upstream")
	if key == "" || role == "" || pgroles.Key(upstream) != key || f.CredentialRef != upstream+"/"+role {
		return notRevoked("the finding does not name its upstream and role consistently: NOT revoked")
	}
	if p.src == nil {
		return notRevoked("no integrations source: NOT revoked")
	}
	r, err := p.src.Get(ctx, key)
	if err != nil {
		return notRevoked(fmt.Sprintf("integration %s is not usable (%s): NOT revoked; run ALTER ROLE %s NOLOGIN as a DBA",
			key, shadow.Clean(err.Error(), 200), pgsql.QuoteIdent(role)))
	}
	u, err := pgroles.ParseUpstream(r)
	if err != nil {
		return notRevoked("integration " + key + " settings are invalid: NOT revoked")
	}
	list, _ := p.src.List(ctx, pgroles.System)
	sys := p.systemRoles(ctx, append(list, r))
	if sys[role] || strings.HasPrefix(role, "fortik_a_") {
		return notRevoked("role " + role + " is one of Fortik's own roles: refused")
	}
	conn, err := connectAdmin(ctx, u, "fortik:shadow:revoke")
	if err != nil {
		return notRevoked(err.Error() + ": NOT revoked")
	}
	defer conn.Close(context.WithoutCancel(ctx))
	var super bool
	err = conn.QueryRow(ctx, `SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = $1`, role).Scan(&super)
	if errors.Is(err, pgx.ErrNoRows) {
		return notRevoked("role " + role + " no longer exists on " + key + ": nothing to revoke (dismiss the finding if that is expected)")
	}
	if err != nil {
		return notRevoked("look up role: " + pgErr(err) + ": NOT revoked")
	}
	if super {
		return shadow.RevokeResult{Outcome: shadow.OutcomeManualRequired, Detail: fmt.Sprintf(
			"role %s is a superuser: Fortik does not alter superusers; a DBA must run ALTER ROLE %s NOSUPERUSER NOLOGIN and end its sessions",
			role, pgsql.QuoteIdent(role))}
	}
	q := pgsql.QuoteIdent(role)
	if _, err := conn.Exec(ctx, "ALTER ROLE "+q+" NOLOGIN"); err != nil {
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "42501" {
			return notRevoked(fmt.Sprintf("the integration's admin role %s may not alter %s (%s): NOT revoked; run ALTER ROLE %s NOLOGIN as a superuser, or grant the admin role ADMIN OPTION on it",
				u.AdminUser, role, pe.Message, q))
		}
		return notRevoked("ALTER ROLE NOLOGIN failed: " + pgErr(err) + ": NOT revoked")
	}
	var live, killed int64
	err = conn.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE pg_catalog.pg_terminate_backend(pid))
		FROM pg_catalog.pg_stat_activity WHERE usename = $1 AND pid <> pg_catalog.pg_backend_pid()`, role).Scan(&live, &killed)
	if err != nil {
		return notRevoked(fmt.Sprintf("role %s set NOLOGIN (no new logins) but its live sessions were NOT terminated (%s); grant the admin role pg_signal_backend or terminate them as a DBA",
			role, pgErr(err)))
	}
	if killed < live {
		return notRevoked(fmt.Sprintf("role %s set NOLOGIN (no new logins) but only %d of %d live sessions were terminated", role, killed, live))
	}
	p.log.Warn("shadow postgres role revoked", "upstream", u.Name, "role", role, "sessions_terminated", killed)
	return shadow.RevokeResult{Outcome: shadow.OutcomeRevoked,
		Detail: fmt.Sprintf("%s: role %s set NOLOGIN; %d of %d live sessions terminated (password kept; a DBA can re-enable LOGIN)", key, role, killed, live)}
}
