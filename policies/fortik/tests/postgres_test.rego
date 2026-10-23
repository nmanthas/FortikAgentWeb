package fortik.tests

import data.fortik.decide

test_select_is_green_allow if {
	r := decide.result with input as pg("SELECT", "READ", "prod", {})
	r.class == "green"
	r.decision == "allow"
	r.rule_id == "POL-000"
	not r.ladder_change
	not r.reduced_form
}

test_drop_table_prod_red_hold_step_down_read_only if {
	r := decide.result with input as pg("DROP_TABLE", "DELETE", "prod", {})
	r.class == "red"
	r.decision == "hold"
	r.rule_id == "POL-101"
	r.ladder_change.to == "READ_ONLY"
}

test_drop_table_staging_also_red if {
	r := decide.result with input as pg("DROP_TABLE", "DELETE", "staging", {})
	r.class == "red"
	r.decision == "hold"
	r.rule_id == "POL-101"
}

test_truncate_drop_schema_drop_database_red if {
	every st in ["TRUNCATE", "DROP_SCHEMA", "DROP_DATABASE"] {
		r := decide.result with input as pg(st, "DELETE", "dev", {})
		r.class == "red"
		r.rule_id == "POL-101"
	}
}

test_delete_without_narrow_where_snapshot_first if {
	r := decide.result with input as pg("DELETE", "DELETE", "staging", {"has_where": true, "where_narrow": false, "undo_preparable": true})
	r.class == "yellow"
	r.decision == "allow_reduced"
	r.rule_id == "POL-102"
	r.reduced_form == {"snapshot_rows": true}
	not r.ladder_change
}

test_update_without_where_snapshot_first if {
	r := decide.result with input as pg("UPDATE", "WRITE", "prod", {"has_where": false, "where_narrow": false, "undo_preparable": true})
	r.decision == "allow_reduced"
	r.reduced_form.snapshot_rows == true
}

test_delete_narrow_small_is_green if {
	inp := with_summary(pg("DELETE", "DELETE", "prod", {"has_where": true, "where_narrow": true, "undo_preparable": true}), {"rows_estimate": 1})
	r := decide.result with input as inp
	r.class == "green"
	r.decision == "allow"
}

test_delete_narrow_but_over_threshold_is_yellow if {
	inp := with_summary(pg("DELETE", "DELETE", "prod", {"has_where": true, "where_narrow": true, "undo_preparable": true}), {"rows_estimate": 5000})
	r := decide.result with input as inp
	r.class == "yellow"
	r.decision == "allow_reduced"
	r.rule_id == "POL-102"
}

test_bulk_write_without_undo_is_held if {
	r := decide.result with input as pg("UPDATE", "WRITE", "staging", {"has_where": false, "where_narrow": false, "undo_preparable": false})
	r.class == "yellow"
	r.decision == "hold"
	r.rule_id == "POL-103"
	not r.reduced_form
}

test_bulk_write_too_large_to_snapshot_is_held if {
	inp := with_summary(pg("DELETE", "DELETE", "prod", {"has_where": true, "where_narrow": false, "undo_preparable": true}), {"rows_estimate": 2000000})
	r := decide.result with input as inp
	r.decision == "hold"
	r.rule_id == "POL-103"
	not "POL-102" in rule_ids(r)
}

test_server_side_execution_is_red_isolated if {
	every st in ["COPY_PROGRAM", "COPY_FILE", "DANGEROUS_FUNCTION"] {
		r := decide.result with input as pg(st, "EXECUTE", "staging", {"dangerous_functions": ["pg_read_file"]})
		r.class == "red"
		r.rule_id == "POL-104"
		r.ladder_change.to == "ISOLATED"
	}
}

test_copy_to_stdout_held if {
	r := decide.result with input as pg("COPY_TO_STDOUT", "EXPORT", "prod", {})
	r.class == "yellow"
	r.decision == "hold"
	r.rule_id == "POL-105"
}

test_ddl_on_prod_held if {
	every st in ["DDL_CREATE", "DDL_ALTER", "DROP_OTHER", "MAINTENANCE", "LOCK", "SELECT_INTO"] {
		r := decide.result with input as pg(st, "WRITE", "prod", {})
		r.decision == "hold"
		r.rule_id == "POL-106"
	}
}

test_ddl_on_staging_allowed if {
	r := decide.result with input as pg("DDL_ALTER", "WRITE", "staging", {})
	r.class == "green"
	r.decision == "allow"
}

test_drop_column_prod_red if {
	r := decide.result with input as pg("ALTER_DROP_COLUMN", "DELETE", "prod", {})
	r.class == "red"
	r.rule_id == "POL-107"
	r.ladder_change.to == "READ_ONLY"
}

test_drop_column_staging_held if {
	r := decide.result with input as pg("ALTER_DROP_COLUMN", "DELETE", "staging", {})
	r.class == "yellow"
	r.decision == "hold"
	r.rule_id == "POL-108"
}

test_do_block_held if {
	r := decide.result with input as pg("EXECUTE_BLOCK", "EXECUTE", "dev", {})
	r.decision == "hold"
	r.rule_id == "POL-109"
}

test_unknown_sql_denied_without_step_down if {
	r := decide.result with input as pg("UNKNOWN", "EXECUTE", "prod", {})
	r.class == "red"
	r.decision == "deny"
	r.rule_id == "POL-110"
	not r.ladder_change
}

test_missing_statement_type_denied if {
	inp := mk("postgres", "WRITE", {"environment": "prod"}, {}, 0)
	r := decide.result with input as inp
	r.decision == "deny"
	"POL-110" in rule_ids(r)
}

test_postgres_grant_red if {
	r := decide.result with input as pg("GRANT", "GRANT", "prod", {})
	r.class == "red"
	r.rule_id == "POL-001"
	r.ladder_change.to == "ISOLATED"
}

test_threshold_is_configurable if {
	inp := object.union(
		with_summary(pg("DELETE", "DELETE", "prod", {"has_where": true, "where_narrow": true, "undo_preparable": true}), {"rows_estimate": 50}),
		{"config": {"pg_snapshot_row_threshold": 10}},
	)
	r := decide.result with input as inp
	r.rule_id == "POL-102"
}

test_destructive_ladder_is_configurable if {
	inp := object.union(pg("DROP_TABLE", "DELETE", "prod", {}), {"config": {"pg_destructive_ladder": "QUARANTINED"}})
	r := decide.result with input as inp
	r.ladder_change.to == "QUARANTINED"
}
