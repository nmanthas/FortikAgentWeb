# Postgres rules. Input target keys are produced by the Fortik Postgres proxy:
# statement_type, environment, tables, has_where, where_narrow,
# undo_preparable, dangerous_functions, safe_form; rows_estimate lives in
# payload_summary.
package fortik.rules

pg if act.system == "postgres"

stype := object.get(tgt, "statement_type", "")

env := object.get(tgt, "environment", "")

prod if env == "prod"

tables_str := concat(", ", object.get(tgt, "tables", []))

rows_estimate := object.get(summary, "rows_estimate", -1)

# POL-101: DROP/TRUNCATE is irreversible. Held; a rename-based safe form is
# offered for approval; the agent steps down to Read-only.
findings contains {
	"rule_id": "POL-101",
	"class": "red",
	"reason": sprintf("irreversible %s on %s database (%s)", [stype, env, tables_str]),
	"ladder": cfg.pg_destructive_ladder,
} if {
	pg
	stype in {"DROP_TABLE", "DROP_SCHEMA", "DROP_DATABASE", "TRUNCATE"}
}

# POL-102: DELETE/UPDATE without a narrow WHERE, or over N rows, runs only
# after the affected rows are snapshotted (undo handle prepared first).
pg_bulk_write if {
	pg
	stype in {"DELETE", "UPDATE"}
	not tgt.where_narrow == true
}

pg_bulk_write if {
	pg
	stype in {"DELETE", "UPDATE"}
	rows_estimate > cfg.pg_snapshot_row_threshold
}

findings contains {
	"rule_id": "POL-102",
	"class": "yellow",
	"reason": sprintf("%s on %s without a narrow WHERE or over %d rows: snapshot affected rows first", [stype, tables_str, cfg.pg_snapshot_row_threshold]),
	"reduced_form": {"snapshot_rows": true},
} if {
	pg_bulk_write
	tgt.undo_preparable == true
	rows_estimate <= cfg.pg_snapshot_max_rows
}

# POL-103: a write that needs an undo snapshot but cannot get one is held:
# Fortik never runs a risky write on a guess.
findings contains {
	"rule_id": "POL-103",
	"class": "yellow",
	"reason": sprintf("%s on %s needs an undo snapshot that cannot be prepared (multi-table, no primary key, or over %d rows): approval required", [stype, tables_str, cfg.pg_snapshot_max_rows]),
	"hold": true,
} if {
	pg_bulk_write
	not tgt.undo_preparable == true
}

findings contains {
	"rule_id": "POL-103",
	"class": "yellow",
	"reason": sprintf("%s on %s needs an undo snapshot that cannot be prepared (multi-table, no primary key, or over %d rows): approval required", [stype, tables_str, cfg.pg_snapshot_max_rows]),
	"hold": true,
} if {
	pg_bulk_write
	rows_estimate > cfg.pg_snapshot_max_rows
}

# POL-104: server-side code/file execution and dangerous admin functions.
findings contains {
	"rule_id": "POL-104",
	"class": "red",
	"reason": sprintf("dangerous server-side execution (%s %v)", [stype, object.get(tgt, "dangerous_functions", [])]),
	"ladder": "ISOLATED",
} if {
	pg
	stype in {"COPY_PROGRAM", "COPY_FILE", "DANGEROUS_FUNCTION"}
}

# POL-105: bulk export out of the database (COPY ... TO STDOUT) needs approval.
findings contains {
	"rule_id": "POL-105",
	"class": "yellow",
	"reason": sprintf("bulk export (COPY TO STDOUT) of %s", [tables_str]),
	"hold": true,
} if {
	pg
	stype == "COPY_TO_STDOUT"
}

# POL-106: schema and maintenance changes on production need approval
# (no undo exists for DDL in the MVP).
findings contains {
	"rule_id": "POL-106",
	"class": "yellow",
	"reason": sprintf("%s on production (%s) has no undo: approval required", [stype, tables_str]),
	"hold": true,
} if {
	pg
	prod
	stype in {"DDL_CREATE", "DDL_ALTER", "DROP_OTHER", "MAINTENANCE", "LOCK", "SELECT_INTO"}
}

# POL-107: dropping a column on production destroys data irreversibly.
findings contains {
	"rule_id": "POL-107",
	"class": "red",
	"reason": sprintf("ALTER TABLE ... DROP COLUMN on production (%s) is irreversible", [tables_str]),
	"ladder": cfg.pg_destructive_ladder,
} if {
	pg
	prod
	stype == "ALTER_DROP_COLUMN"
}

# POL-108: dropping a column outside production still loses data: approval.
findings contains {
	"rule_id": "POL-108",
	"class": "yellow",
	"reason": sprintf("ALTER TABLE ... DROP COLUMN on %s (%s) loses data: approval required", [env, tables_str]),
	"hold": true,
} if {
	pg
	not prod
	stype == "ALTER_DROP_COLUMN"
}

# POL-109: DO blocks and procedure calls cannot be inspected: approval.
findings contains {
	"rule_id": "POL-109",
	"class": "yellow",
	"reason": "DO block / CALL cannot be inspected statically: approval required",
	"hold": true,
} if {
	pg
	stype == "EXECUTE_BLOCK"
}

# POL-110: SQL the proxy could not classify fails closed.
findings contains {
	"rule_id": "POL-110",
	"class": "red",
	"reason": "unclassified SQL statement: fail closed",
	"ladder": "NONE",
	"deny": true,
} if {
	pg
	stype in {"UNKNOWN", ""}
}

findings contains {
	"rule_id": "POL-110",
	"class": "red",
	"reason": "malformed statement_type: fail closed",
	"ladder": "NONE",
	"deny": true,
} if {
	pg
	not is_string(stype)
}

# POL-111: MERGE can update or delete many rows and has no undo in the MVP.
findings contains {
	"rule_id": "POL-111",
	"class": "yellow",
	"reason": sprintf("MERGE into %s has no undo in the MVP: approval required", [tables_str]),
	"hold": true,
} if {
	pg
	stype == "MERGE"
}

# POL-112: upserts (INSERT ... ON CONFLICT DO UPDATE) and bulk COPY FROM STDIN
# on production overwrite rows without an undo snapshot: approval.
findings contains {
	"rule_id": "POL-112",
	"class": "yellow",
	"reason": sprintf("%s on production (%s) overwrites rows without undo: approval required", [stype, tables_str]),
	"hold": true,
} if {
	pg
	prod
	stype == "INSERT"
	not tgt.on_conflict_update == false # missing = unknown = held
}

findings contains {
	"rule_id": "POL-112",
	"class": "yellow",
	"reason": sprintf("%s on production (%s) overwrites rows without undo: approval required", [stype, tables_str]),
	"hold": true,
} if {
	pg
	prod
	stype == "COPY_FROM_STDIN"
}

# POL-113: a bulk read of sensitive data (estimated rows above
# pg_bulk_read_rows from a table carrying a sensitive data label, e.g.
# 12,480 customer records) is flagged yellow and waits for approval: the
# first step of the plan's attack scenario.
findings contains {
	"rule_id": "POL-113",
	"class": "yellow",
	"reason": sprintf("bulk read of sensitive data %v: about %d rows from %s (threshold %d): approval required", [sort([l | some l in sensitive]), rows_estimate, tables_str, cfg.pg_bulk_read_rows]),
	"hold": true,
} if {
	pg
	act.verb == "READ"
	count(sensitive) > 0
	rows_estimate > cfg.pg_bulk_read_rows
}

# POL-114: a SELECT of sensitive data with no row estimate fails closed. The
# proxy has no estimate when it cannot plan the read safely before deciding
# (a function outside the safe built-ins, a view or other non-table
# relation, a pipelined statement, an EXPLAIN error or timeout, a
# parameterised read of a never-analysed table). Unknown size is treated as
# a possible bulk read, never as a small one.
findings contains {
	"rule_id": "POL-114",
	"class": "yellow",
	"reason": sprintf("read of sensitive data %v from %s with no row estimate (the size could not be checked safely before the read): approval required", [sort([l | some l in sensitive]), tables_str]),
	"hold": true,
} if {
	pg
	act.verb == "READ"
	stype == "SELECT"
	count(sensitive) > 0
	not is_number(object.get(summary, "rows_estimate", null))
}
