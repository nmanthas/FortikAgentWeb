package pgroles

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"fortik/internal/integrations"
	"fortik/internal/pgsql"
)

// Test implements integrations.Tester for postgres:<name>. It logs in as the
// admin user and checks everything per-agent roles, revocation and undo
// snapshots need:
//   - read_role and write_role exist, and read_role is not a member of
//     write_role (read_only agents would otherwise write);
//   - the admin is superuser, or has CREATEROLE (and, on PG 16+, ADMIN OPTION
//     on both roles, needed to grant them);
//   - the admin is superuser or a member of pg_signal_backend (revocation
//     terminates the agent's live sessions);
//   - schema fortik_undo exists, write_role has USAGE and CREATE on it (the
//     agent's role creates undo snapshots there) and the admin has USAGE on it
//     (snapshot verification and undo run as the admin).
//
// The returned error is safe to show in the UI: it never contains secrets.
func (m *Manager) Test(ctx context.Context, r integrations.Resolved) error { return Test(ctx, r) }

// Test is the Tester logic without a Manager (the integrations API can call
// it directly).
func Test(ctx context.Context, r integrations.Resolved) error {
	u, err := ParseUpstream(r)
	if err != nil {
		return err
	}
	conn, err := adminConnect(ctx, u, "fortik:pgroles:test")
	if err != nil {
		return fmt.Errorf("connect as %s to %s:%d/%s failed: %s", u.AdminUser, u.Host, u.Port, u.Database, sanitize(err))
	}
	defer conn.Close(context.WithoutCancel(ctx))

	var (
		super, createRole, readOK, writeOK, readInWrite                              bool
		adminRead, adminWrite, signal, schemaOK, writeUsage, writeCreate, adminUsage bool
		version                                                                      int
	)
	err = conn.QueryRow(ctx, `SELECT r.rolsuper, r.rolcreaterole,
       pg_catalog.current_setting('server_version_num')::int,
       EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = $1),
       EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = $2),
       pg_catalog.to_regnamespace($3) IS NOT NULL
FROM pg_catalog.pg_roles r WHERE r.rolname = current_user`, u.ReadRole, u.WriteRole, pgsql.QuoteIdent(pgsql.SnapshotSchema)).
		Scan(&super, &createRole, &version, &readOK, &writeOK, &schemaOK)
	if err != nil {
		return fmt.Errorf("inspect admin role: %s", sanitize(err))
	}
	var problems []string
	if !readOK {
		problems = append(problems, fmt.Sprintf("read_role %q does not exist", u.ReadRole))
	}
	if !writeOK {
		problems = append(problems, fmt.Sprintf("write_role %q does not exist", u.WriteRole))
	}
	if readOK && writeOK {
		err = conn.QueryRow(ctx, `SELECT
       pg_catalog.pg_has_role(r.oid, w.oid, 'MEMBER'),
       pg_catalog.pg_has_role(current_user, r.oid, 'MEMBER WITH ADMIN OPTION'),
       pg_catalog.pg_has_role(current_user, w.oid, 'MEMBER WITH ADMIN OPTION')
FROM pg_catalog.pg_roles r, pg_catalog.pg_roles w WHERE r.rolname = $1 AND w.rolname = $2`, u.ReadRole, u.WriteRole).
			Scan(&readInWrite, &adminRead, &adminWrite)
		if err != nil {
			return fmt.Errorf("inspect roles: %s", sanitize(err))
		}
		if readInWrite {
			problems = append(problems, fmt.Sprintf("read_role %q is a member of write_role %q, so read_only agents could write", u.ReadRole, u.WriteRole))
		}
	}
	switch {
	case super:
	case !createRole:
		problems = append(problems, fmt.Sprintf("admin user %q needs CREATEROLE (or superuser) to manage per-agent roles", u.AdminUser))
	case version >= 160000 && readOK && writeOK && (!adminRead || !adminWrite):
		problems = append(problems, fmt.Sprintf("admin user %q needs ADMIN OPTION on %q and %q (GRANT %s, %s TO %s WITH ADMIN OPTION)",
			u.AdminUser, u.ReadRole, u.WriteRole, pgsql.QuoteIdent(u.ReadRole), pgsql.QuoteIdent(u.WriteRole), pgsql.QuoteIdent(u.AdminUser)))
	}
	if !super {
		if err := conn.QueryRow(ctx, `SELECT pg_catalog.pg_has_role(current_user, 'pg_signal_backend', 'USAGE')`).Scan(&signal); err != nil {
			return fmt.Errorf("inspect pg_signal_backend: %s", sanitize(err))
		}
		if !signal {
			problems = append(problems, fmt.Sprintf("admin user %q needs pg_signal_backend (GRANT pg_signal_backend TO %s) so revocation can terminate agent sessions",
				u.AdminUser, pgsql.QuoteIdent(u.AdminUser)))
		}
	}
	if !schemaOK {
		problems = append(problems, fmt.Sprintf("schema %s does not exist (CREATE SCHEMA %s; GRANT USAGE, CREATE ON SCHEMA %s TO %s)",
			pgsql.SnapshotSchema, pgsql.SnapshotSchema, pgsql.SnapshotSchema, pgsql.QuoteIdent(u.WriteRole)))
	} else {
		if writeOK {
			err = conn.QueryRow(ctx, `SELECT pg_catalog.has_schema_privilege(w.oid, $2::regnamespace, 'USAGE'),
       pg_catalog.has_schema_privilege(w.oid, $2::regnamespace, 'CREATE')
FROM pg_catalog.pg_roles w WHERE w.rolname = $1`, u.WriteRole, pgsql.QuoteIdent(pgsql.SnapshotSchema)).Scan(&writeUsage, &writeCreate)
			if err != nil {
				return fmt.Errorf("inspect schema privileges: %s", sanitize(err))
			}
			if !writeUsage || !writeCreate {
				problems = append(problems, fmt.Sprintf("write_role %q needs USAGE and CREATE on schema %s for undo snapshots", u.WriteRole, pgsql.SnapshotSchema))
			}
		}
		if err := conn.QueryRow(ctx, `SELECT pg_catalog.has_schema_privilege($1::regnamespace, 'USAGE')`,
			pgsql.QuoteIdent(pgsql.SnapshotSchema)).Scan(&adminUsage); err != nil {
			return fmt.Errorf("inspect schema privileges: %s", sanitize(err))
		}
		if !adminUsage {
			problems = append(problems, fmt.Sprintf("admin user %q needs USAGE on schema %s (undo restores run as the admin)", u.AdminUser, pgsql.SnapshotSchema))
		}
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}
