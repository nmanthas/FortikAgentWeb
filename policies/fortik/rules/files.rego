# File rules (docs/PHASE3_DESIGN.md §3.4) for Claude Code's file tools
# (system "files": Write/Edit/MultiEdit/NotebookEdit = WRITE; Read, Glob,
# Grep = READ) and for shell commands that write or read sensitive paths.
# Adapter contract (target, system "files"): path, sensitive_path (bool),
# sensitive_kind (credentials | agent_config | workflow | persistence |
# system), operation. Detection only: these rules refuse, never execute.
#
#   POL-511 red         writing a sensitive path (credentials, agent settings,
#                       CI workflows: POL-303 semantics, shell rc files, system)
#   POL-512 yellow hold reading credential files
package fortik.rules

fil_sensitive if tgt.sensitive_path == true

fil_kind := k if {
	k := tgt.sensitive_kind
	is_string(k)
	k != ""
} else := "sensitive"

findings contains {
	"rule_id": "POL-511",
	"class": "red",
	"reason": sprintf("write to sensitive path %v (%s)", [object.get(tgt, "path", ""), fil_kind]),
	"ladder": "NONE",
} if {
	act.system == "files"
	act.verb != "READ"
	fil_sensitive
}

findings contains {
	"rule_id": "POL-511",
	"class": "red",
	"reason": sprintf("shell command writes sensitive paths %v (%v)", [tgt.sensitive_writes, object.get(tgt, "sensitive_kinds", [])]),
	"ladder": "NONE",
} if {
	act.system == "shell"
	w := tgt.sensitive_writes
	is_array(w)
	count(w) > 0
}

findings contains {
	"rule_id": "POL-512",
	"class": "yellow",
	"reason": sprintf("read of credential file %v: approval required", [object.get(tgt, "path", "")]),
	"hold": true,
} if {
	act.system == "files"
	act.verb == "READ"
	fil_sensitive
	fil_kind == "credentials"
}

findings contains {
	"rule_id": "POL-512",
	"class": "yellow",
	"reason": sprintf("shell command reads credential files %v: approval required", [tgt.sensitive_reads]),
	"hold": true,
} if {
	act.system == "shell"
	r := tgt.sensitive_reads
	is_array(r)
	count(r) > 0
}

# A malformed sensitive marker fails closed.
findings contains {
	"rule_id": "POL-009",
	"class": "red",
	"reason": "malformed target.sensitive_path (must be boolean): fail closed",
	"ladder": "NONE",
	"deny": true,
} if {
	act.system == "files"
	v := tgt.sensitive_path
	not is_boolean(v)
}
