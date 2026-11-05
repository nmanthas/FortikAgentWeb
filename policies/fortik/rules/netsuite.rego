# NetSuite rules (Milestone 1, internal/netsuite). Adapter contract (the app
# gateway, /gw/netsuite; field NAMES only, never values):
#   target.operation  get | list | create | update | upsert | delete |
#                     transform | query | observed_change (audit, after the fact)
#   target.record_type, target.record_id, target.to_record_type (lower-cased)
#   target.fields     names of the fields a write sets
#   target.query_tables, target.limit (SuiteQL)
# Lists and thresholds: data.fortik.config.netsuite. Business meaning is
# inferred only from what the request itself shows (record type, field names):
# nothing is classified as a payment or a bank change without that evidence.
#
#   POL-1001 yellow  update of one record: snapshot the changed fields first (undo)
#   POL-1002 red     delete a record: held, never run unchanged (no reliable undo)
#   POL-1003 yellow  create or transform into a payment record: held for
#                    config.netsuite.payment_approvals approvers (not undoable)
#   POL-1004 yellow  a change to bank or payment details: held for approval
#   POL-1005 red     a change to financial setup (accounting periods, chart of
#                    accounts, subsidiaries, currencies, tax): held
#   POL-1006 red     malformed NetSuite target: denied (fail closed)
#   POL-1009 yellow  upsert (PUT by id or external id): no verified undo: held
# Access-profile gates POL-1007 (record type) and POL-1008 (SuiteQL) are in
# fortik.access.
package fortik.rules

netsuite if act.system == "netsuite"

ns_cfg := c if {
	c := cfg.netsuite
	is_object(c)
} else := {}

ns_set(k) := {lower(x) | some x in object.get(ns_cfg, k, []); is_string(x)}

ns_op := o if {
	o := tgt.operation
	is_string(o)
} else := ""

ns_ops := {"get", "list", "create", "update", "upsert", "delete", "transform", "query", "observed_change"}

ns_record_ops := {"get", "list", "create", "update", "upsert", "delete", "transform"}

ns_type := lower(t) if {
	t := tgt.record_type
	is_string(t)
} else := ""

ns_to := lower(t) if {
	t := tgt.to_record_type
	is_string(t)
} else := ""

ns_fields := {lower(f) | some f in object.get(tgt, "fields", []); is_string(f)}

ns_write if ns_op in {"create", "update", "upsert", "transform"}

# --- POL-1006: malformed target -------------------------------------------------

ns_malformed contains "operation is missing or unknown" if {
	netsuite
	not ns_op in ns_ops
	not qs_op_ok
	act.verb != "UNKNOWN"
}

ns_malformed contains "record operation without a record type" if {
	netsuite
	ns_op in ns_record_ops
	ns_type == ""
}

ns_malformed contains "fields is not a list of names" if {
	netsuite
	f := object.get(tgt, "fields", [])
	not is_array(f)
}

ns_malformed contains "fields is not a list of names" if {
	netsuite
	some f in object.get(tgt, "fields", [])
	not is_string(f)
}

findings contains {
	"rule_id": "POL-1006",
	"class": "red",
	"reason": sprintf("malformed NetSuite action: %s", [m]),
	"ladder": "NONE",
	"deny": true,
} if {
	some m in ns_malformed
}

# --- POL-1001: updates are snapshotted first -----------------------------------

# REST updates always; MCP updates only when mcp_writes_require_approval is
# false (see netsuite_quickstart.rego).
ns_snapshot_transport if not ns_quickstart

ns_snapshot_transport if qs_snapshot_update

findings contains {
	"rule_id": "POL-1001",
	"class": "yellow",
	"reason": sprintf("update of %s %v: the previous values of %d field(s) are snapshotted first (undoable)", [ns_type, object.get(tgt, "record_id", "?"), count(ns_fields)]),
	"reduced_form": {"record_snapshot": true},
} if {
	netsuite
	ns_snapshot_transport # MCP updates are held instead (POL-1120) unless configured otherwise
	ns_op == "update"
	ns_type != ""
	is_string(tgt.record_id)
}

# --- POL-1002: deletes ------------------------------------------------------------

findings contains {
	"rule_id": "POL-1002",
	"class": "red",
	"reason": sprintf("delete of NetSuite %s %v: a deleted record cannot be restored through the API", [ns_type, object.get(tgt, "record_id", "?")]),
	"ladder": "READ_ONLY",
} if {
	netsuite
	ns_op == "delete"
}

# --- POL-1003: payments -------------------------------------------------------

ns_payment if {
	ns_op == "create"
	ns_type in ns_set("payment_record_types")
}

ns_payment if {
	ns_op == "transform"
	ns_to in ns_set("payment_record_types")
}

ns_payment_approvals := n if {
	n := ns_cfg.payment_approvals
	is_number(n)
	n >= 1
} else := 2

findings contains {
	"rule_id": "POL-1003",
	"class": "yellow",
	"reason": sprintf("creates a NetSuite payment record (%s): money movement is not undoable, %d approver(s) required", [object.get({true: ns_to}, ns_op == "transform", ns_type), ns_payment_approvals]),
	"hold": true,
	"approvals_required": ns_payment_approvals,
} if {
	netsuite
	ns_payment
}

# --- POL-1004: bank or payment details ------------------------------------------

ns_bank_change if {
	ns_write
	ns_type in ns_set("bank_detail_record_types")
}

ns_bank_change if {
	ns_write
	ns_type in ns_set("bank_field_record_types")
	some f in ns_fields
	some p in ns_set("bank_field_patterns")
	contains(f, p)
}

findings contains {
	"rule_id": "POL-1004",
	"class": "yellow",
	"reason": sprintf("changes bank or payment details on NetSuite %s (fields %v): approval required", [ns_type, sort([f | some f in ns_fields])]),
	"hold": true,
} if {
	netsuite
	ns_bank_change
}

# --- POL-1005: financial setup ----------------------------------------------------

findings contains {
	"rule_id": "POL-1005",
	"class": "red",
	"reason": sprintf("changes NetSuite financial setup (%s): held", [ns_type]),
	"ladder": "READ_ONLY",
} if {
	netsuite
	ns_op in {"create", "update", "upsert", "delete", "transform"}
	ns_type in ns_set("financial_setup_record_types")
}

# --- POL-1009: upserts ---------------------------------------------------------

findings contains {
	"rule_id": "POL-1009",
	"class": "yellow",
	"reason": sprintf("upsert of NetSuite %s %v: no verified undo for a create-or-replace: approval required", [ns_type, object.get(tgt, "record_id", "?")]),
	"hold": true,
} if {
	netsuite
	ns_op == "upsert"
}
