# Shared helpers and system-independent rules.
#
# Every rule contributes one finding to `findings`:
#   {"rule_id": "POL-xxx", "class": "green|yellow|red", "reason": "...",
#    optional "reduced_form": {...}   (yellow: how the action may run),
#    optional "hold": true            (yellow: needs a human, no reduced form),
#    optional "ladder": "<LEVEL>"     (red: level to step the agent down to;
#                                      "NONE" = do not step down)}
# fortik.decide aggregates the findings into one decision.
package fortik.rules

cfg := object.union(data.fortik.config, object.get(input, "config", {}))

act := input.action

tgt := object.get(act, "target", {})

summary := object.get(act, "payload_summary", {})

labels := {l | some l in object.get(summary, "data_labels", [])}

sensitive := labels & {l | some l in cfg.sensitive_labels}

known_verbs := {"READ", "WRITE", "SEND", "SPEND", "EXECUTE", "DELETE", "EXPORT", "GRANT", "DELEGATE", "REMEMBER"}

# Destination outside the company: adapters set target.external = true or a
# positive target.external_domains count.
external if tgt.external == true

external if object.get(tgt, "external_domains", 0) > 0

# POL-001: any GRANT (permission, role or IAM change) on any system is red.
findings contains {
	"rule_id": "POL-001",
	"class": "red",
	"reason": sprintf("GRANT on %s is always red (permission/role/IAM change)", [act.system]),
	"ladder": "ISOLATED",
} if {
	act.verb == "GRANT"
}

# POL-002: unknown verb or system fails closed. Classified red so it can never
# run, but the agent is not stepped down for hitting a classification gap.
findings contains {
	"rule_id": "POL-002",
	"class": "red",
	"reason": sprintf("unclassified action (system=%v, verb=%v): fail closed", [act.system, act.verb]),
	"ladder": "NONE",
	"deny": true,
} if {
	not act.verb in known_verbs
}

findings contains {
	"rule_id": "POL-002",
	"class": "red",
	"reason": sprintf("unclassified action (system=%v, verb=%v): fail closed", [act.system, act.verb]),
	"ladder": "NONE",
	"deny": true,
} if {
	not act.system in {s | some s in cfg.known_systems}
}

# Systems that have a dedicated rule set. Everything else that is a known
# system but has no rules yet must not silently default to green.
rule_systems := {"postgres", "gmail", "drive", "github", "aws", "shell", "files", "http", "mcp", "a2a", "agents", "memory"}

# Systems whose rule sets cover only some verbs/operations (Phase 3). For
# these, POL-005 still holds every non-READ action that `covered` does not
# name, so a verb no rule examines never defaults to green.
partial_rule_systems := {"shell", "files", "http", "mcp", "a2a", "agents", "memory"}

# shell: every classified command (target.classifier set by the hook's
# shell classifier) is examined by shell.rego (POL-501..508).
covered if {
	act.system == "shell"
	tgt.classifier == "fortik-shell/1"
}

# files: writes are examined by files.rego (POL-511).
covered if {
	act.system == "files"
	act.verb == "WRITE"
}

# http: uploads are examined by http.rego (POL-505).
covered if {
	act.system == "http"
	act.verb in {"SEND", "EXPORT", "WRITE"}
}

# a2a: delegations are decided by the delegation gates (POL-601..604) and
# the a2a access profile; WRITE on a2a is task management of a delegated
# task (tasks/cancel, push-notification config), under the same gates.
covered if {
	act.system == "a2a"
	act.verb in {"DELEGATE", "WRITE"}
}

# agents: spawn registrations are decided by the population gates
# (POL-701..); anything else is POL-706.
covered if {
	act.system == "agents"
	act.verb == "DELEGATE"
	object.get(tgt, "operation", "") == "spawn"
}

# mcp: mcp.rego is the rule set for every tool call: unmapped tools
# (POL-801) and DELETE/SEND/EXPORT (POL-802) are held, verbs that disagree
# with the verb table are denied (POL-803); a mapped WRITE/REMEMBER tool
# runs under the mcp access profile (POL-029).
# A non-READ mcp action that names no tool is not a tools/call: POL-005.
covered if {
	act.system == "mcp"
	mcp_tool
}

# memory: gateway writes that name their store and namespace are examined
# by policies/fortik/memory (POL-903 staging, POL-904 sensitive labels).
# DELETE (not undoable) and every other non-READ verb stay held by POL-005.
covered if {
	act.system == "memory"
	act.verb == "REMEMBER"
	is_string(tgt.store)
	is_string(tgt.namespace)
}

# POL-003: sensitive data leaving the company through a system without its
# own data-egress rule (Gmail/Drive have POL-201/POL-212).
findings contains {
	"rule_id": "POL-003",
	"class": "red",
	"reason": sprintf("sensitive data %v sent outside the company via %s", [sort([l | some l in sensitive]), act.system]),
	"ladder": "ISOLATED",
} if {
	act.verb in {"SEND", "EXPORT", "WRITE", "DELEGATE"}
	external
	count(sensitive) > 0
	not act.system in {"gmail", "drive"}
}

# POL-005: a side-effecting action on a known system that has no dedicated
# rules yet (mcp, a2a, http, shell, memory until their adapters ship) needs a human.
findings contains {
	"rule_id": "POL-005",
	"class": "yellow",
	"reason": sprintf("no system-specific policy yet for %s %s: approval required", [act.system, act.verb]),
	"hold": true,
} if {
	act.system in {s | some s in cfg.known_systems}
	not act.system in rule_systems
	act.verb in known_verbs
	act.verb != "READ"
}

# POL-005 for partially covered systems: a non-READ verb/operation their
# rule set does not examine needs a human.
findings contains {
	"rule_id": "POL-005",
	"class": "yellow",
	"reason": sprintf("no system-specific policy for %s %s: approval required", [act.system, act.verb]),
	"hold": true,
} if {
	act.system in {s | some s in cfg.known_systems}
	act.system in partial_rule_systems
	act.verb in known_verbs
	act.verb != "READ"
	not covered
}

# POL-007: deleting mail or files is not undoable in the MVP.
findings contains {
	"rule_id": "POL-007",
	"class": "yellow",
	"reason": sprintf("%s DELETE is not undoable in the MVP: approval required", [act.system]),
	"hold": true,
} if {
	act.system in {"gmail", "drive"}
	act.verb == "DELETE"
}

# POL-008: spend above the generic threshold on systems without their own
# spend rule (AWS has POL-403).
findings contains {
	"rule_id": "POL-008",
	"class": "yellow",
	"reason": sprintf("spend estimate $%v exceeds $%v: approval required", [act.est_cost_usd, cfg.spend_approval_usd]),
	"hold": true,
} if {
	act.system != "aws"
	object.get(act, "est_cost_usd", 0) > cfg.spend_approval_usd
}

# POL-009: adapter sent a malformed field the rules depend on. Rules compare
# with `== true`, so a string "true" would otherwise silently skip them.
bool_fields := {"external", "protected", "backup", "has_where", "where_narrow", "undo_preparable", "on_conflict_update", "merge_has_delete", "volatile_where"}

findings contains {
	"rule_id": "POL-009",
	"class": "red",
	"reason": sprintf("malformed target.%s (must be boolean): fail closed", [k]),
	"ladder": "NONE",
	"deny": true,
} if {
	some k, v in tgt
	k in bool_fields
	not is_boolean(v)
}

findings contains {
	"rule_id": "POL-009",
	"class": "red",
	"reason": "malformed target.external_domains (must be a number): fail closed",
	"ladder": "NONE",
	"deny": true,
} if {
	v := tgt.external_domains
	not is_number(v)
}

# POL-008: a SPEND with no cost estimate cannot be bounded: approval.
findings contains {
	"rule_id": "POL-008",
	"class": "yellow",
	"reason": sprintf("%s SPEND without a cost estimate: approval required", [act.system]),
	"hold": true,
} if {
	act.verb == "SPEND"
	object.get(act, "est_cost_usd", 0) <= 0
}
