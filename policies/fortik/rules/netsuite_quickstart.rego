# NetSuite QuickStart MCP rules (QuickStart brief, Milestone 2). Agents call
# QuickStart's MCP tools through Fortik's MCP endpoint (internal/nsquickstart);
# each tools/call is decided as system netsuite with:
#   target.transport "mcp", target.integration "netsuite_quickstart"
#   target.tool, target.operation (data.fortik.netsuite_quickstart.tools)
#   target.record_type / record_id / fields / sublists (names, never values)
#   target.tool_offered, catalog_current, schema_errors, understood,
#   not_understood, undo_possible, args_sha256 (approval binding)
# The NetSuite rules (netsuite.rego) apply to the same target: deletes
# (POL-1002), payments (POL-1003), bank details (POL-1004) and financial
# setup (POL-1005), and the netsuite access profile.
#
#   POL-1101 red    deny  tool not offered, tool list not current, or
#                         arguments outside the discovered schema
#   POL-1102 red    deny  a change to a protected preference (MCP_SERVER_ENABLED)
#   POL-1103 yellow       a company preference change: 2 approvers
#   POL-1104 red          attachment delete: held, never run unchanged
#   POL-1105 yellow       money movement or ledger change (payment transforms,
#                         approve/void/unapply, money record types): payment approvers
#   POL-1106 yellow       email or support request: external effect, not undoable
#   POL-1107 yellow       the call could not be fully understood: review
#   POL-1120 yellow       every other NetSuite MCP write: held for approval
#                         (an update that can be snapshotted runs under
#                         POL-1001 instead when
#                         config.netsuite.mcp_writes_require_approval is false)
# Reads have no finding (green) and run under the access profile, the
# control level, suspensions, delegation and rate limits.
package fortik.rules

# Every NetSuite MCP connection: the QuickStart MCP server and a full
# account's AI Connector Service (integration platform Milestone 1). The name
# is kept from the QuickStart milestones.
ns_quickstart if {
	netsuite
	tgt.transport == "mcp"
	tgt.integration in {"netsuite_quickstart", "netsuite_mcp"}
}

# config.netsuite.mcp_writes_require_approval (default true): MCP updates are
# held for approval even when the same update over REST would run after a
# snapshot (POL-1001). The setting records that difference as a deliberate
# rollout choice, not a difference in evidence: both transports show the
# record, the fields and their new values, and both can snapshot plain
# fields. Set it false to give MCP updates REST's treatment.
mcp_writes_held if {
	object.get(object.get(cfg, "netsuite", {}), "mcp_writes_require_approval", true) != false
}

# An MCP update REST would run after a snapshot (POL-1001 applies instead).
qs_snapshot_update if {
	not mcp_writes_held
	ns_op == "update"
	tgt.undo_possible == true
	tgt.understood == true
}

qs_cfg := c if {
	c := data.fortik.netsuite_quickstart
	is_object(c)
} else := {}

qs_ops := {
	"describe", "app_read", "preference_read", "report", "get", "list", "list_tools",
	"create", "update", "delete", "record_action", "transform", "attachment",
	"upload_temp_file", "send_email", "preference_write", "dismiss_notification", "support_request",
}

qs_op_ok if {
	ns_quickstart
	ns_op in qs_ops
}

qs_str(k) := s if {
	s := tgt[k]
	is_string(s)
} else := ""

qs_set(k) := {lower(x) | some x in object.get(qs_cfg, k, []); is_string(x)}

qs_undo_note := "undo: the changed fields are snapshotted before the update" if {
	tgt.undo_possible == true
} else := "undo: not available for this call"

qs_label := "QuickStart" if {
	tgt.integration == "netsuite_quickstart"
} else := "NetSuite MCP"

# --- POL-1101: only what the server currently offers, as its schema says ----

qs_invalid contains sprintf("tool %v is not offered by the server's current tool list", [qs_str("tool")]) if {
	ns_quickstart
	tgt.tool_offered != true
}

qs_invalid contains "the tool list was not verified for the current settings or token (run Test connection)" if {
	ns_quickstart
	tgt.catalog_current != true
}

qs_invalid contains sprintf("arguments do not match the tool's discovered schema: %v", [concat("; ", errs)]) if {
	ns_quickstart
	errs := [e | some e in object.get(tgt, "schema_errors", []); is_string(e)]
	count(errs) > 0
}

findings contains {
	"rule_id": "POL-1101",
	"class": "red",
	"reason": sprintf("%s call refused: %s", [qs_label, m]),
	"ladder": "NONE",
	"deny": true,
} if {
	some m in qs_invalid
}

# --- POL-1102 / POL-1103: preferences ------------------------------------------

findings contains {
	"rule_id": "POL-1102",
	"class": "red",
	"reason": sprintf("changing QuickStart preference %v is refused: it governs the MCP server agents use", [qs_str("preference_key")]),
	"ladder": "NONE",
	"deny": true,
} if {
	ns_quickstart
	ns_op == "preference_write"
	lower(qs_str("preference_key")) in qs_set("protected_preferences")
}

findings contains {
	"rule_id": "POL-1103",
	"class": "yellow",
	"reason": sprintf("changes QuickStart company preference %v (no Ask Oracle review for MCP preference updates; previous value not reported): 2 approvers required", [qs_str("preference_key")]),
	"hold": true,
	"approvals_required": 2,
} if {
	ns_quickstart
	ns_op == "preference_write"
}

# --- POL-1104: attachment delete ------------------------------------------------

findings contains {
	"rule_id": "POL-1104",
	"class": "red",
	"reason": sprintf("removes an attachment from %v %v: not undoable and not safely retryable", [ns_type, object.get(tgt, "record_id", "?")]),
	"ladder": "NONE",
} if {
	ns_quickstart
	ns_op == "attachment"
	qs_str("attachment_operation") == "delete"
}

# --- POL-1105: money movement and ledger changes -----------------------------
# Evidence (live get_record_model, 2026-10-25): transforms such as
# payVendorBill, invoiceToCustomerPayment, salesOrderToCustomerDeposit,
# creditVendorBill, reverseJournalEntry; record actions approve, void,
# unapply; money and ledger record types (BankTransfer, VendorPayment,
# JournalEntry, ...).

qs_money_reason contains sprintf("%v %v", [ns_op, concat("", [qs_str("transform_id"), qs_str("action_id")])]) if {
	ns_quickstart
	ns_op in {"transform", "record_action"}
	some k in ["transform_id", "action_id"]
	v := lower(qs_str(k))
	v != ""
	some p in qs_set("payment_transform_patterns")
	contains(v, p)
}

qs_money_reason contains sprintf("record action %v", [qs_str("action_id")]) if {
	ns_quickstart
	ns_op == "record_action"
	lower(qs_str("action_id")) in qs_set("high_impact_actions")
}

qs_money_reason contains sprintf("%v of a %v", [ns_op, ns_type]) if {
	ns_quickstart
	ns_op in {"create", "update", "delete"}
	ns_type in qs_set("money_record_types")
}

findings contains {
	"rule_id": "POL-1105",
	"class": "yellow",
	"reason": sprintf("%v on QuickStart %v %v moves money or posts to the ledger: not undoable, %d approver(s) required", [concat(", ", sort([r | some r in qs_money_reason])), ns_type, object.get(tgt, "record_id", ""), ns_payment_approvals]),
	"hold": true,
	"approvals_required": ns_payment_approvals,
} if {
	count(qs_money_reason) > 0
}

# --- POL-1106: external effects --------------------------------------------------

findings contains {
	"rule_id": "POL-1106",
	"class": "yellow",
	"reason": sprintf("sends a record email from QuickStart (%v recipient override(s), domains %v): external effect, a repeat sends it twice, not undoable", [object.get(tgt, "recipient_overrides", 0), object.get(tgt, "recipient_domains", [])]),
	"hold": true,
} if {
	ns_quickstart
	ns_op == "send_email"
}

findings contains {
	"rule_id": "POL-1106",
	"class": "yellow",
	"reason": "submits a QuickStart support request to Oracle: external effect, not undoable",
	"hold": true,
} if {
	ns_quickstart
	ns_op == "support_request"
}

# --- POL-1107: not understood ------------------------------------------------------

findings contains {
	"rule_id": "POL-1107",
	"class": "yellow",
	"reason": sprintf("QuickStart %v could not be fully understood (%v): review required", [qs_str("tool"), concat("; ", [m | some m in object.get(tgt, "not_understood", []); is_string(m)])]),
	"hold": true,
} if {
	ns_quickstart
	tgt.understood != true
	act.verb != "READ"
}

# --- POL-1120: every other write ---------------------------------------------------

findings contains {
	"rule_id": "POL-1120",
	"class": "yellow",
	"reason": sprintf("NetSuite MCP %v (%v %v %v) is held for approval: writes through MCP are not run without review (%s)", [qs_str("tool"), ns_op, ns_type, object.get(tgt, "record_id", ""), qs_undo_note]),
	"hold": true,
} if {
	ns_quickstart
	act.verb != "READ"
	not qs_snapshot_update
}
