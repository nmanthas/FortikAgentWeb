# Shell rules (docs/PHASE3_DESIGN.md §3.4): refusal rules for commands a
# coding agent asks to run through the Claude Code hook. The hook's shell
# classifier (internal/hook) never runs anything; it only describes the
# command line as a target (detection data), and these rules decide whether
# the command may run. Adapter contract (target, system "shell"):
#   classifier "fortik-shell/1", commands, operations, external_hosts,
#   uploads, upload_sensitive, pipes_to_shell, direct_db, db_host, dynamic,
#   privilege, git [{operation, remote, branch}], gh [{operation, repo}],
#   destructive [{command, kind, scope, path}], aws_actions, paths,
#   sensitive_writes, sensitive_reads.
#
# The hook refuses before anything runs, so these red rules do not step the
# agent down ("ladder": "NONE"); the refusal and the record are the control.
#
#   POL-501 red   database client connecting directly (not via the Fortik proxy)
#   POL-502 red   downloaded or decoded content piped into a shell/interpreter
#   POL-503 red   destructive command on catastrophic/remote/disk targets;
#           yellow hold outside the project, on the project root or unknown
#   POL-504 red   privilege escalation (sudo, su, doas)
#   POL-505 yellow hold  uploads / remote copy / remote shell (red with secrets)
#   POL-506 yellow hold  dynamic or unclassified command
#   POL-507 red   force push or branch deletion on a protected branch, GitHub
#           CLI repo deletion / secret changes; yellow hold for force push to
#           an unknown branch, PR merges and workflow runs
#   POL-508 aws CLI calls judged like AWS actions (red identity/deletion,
#           yellow hold for other non-read calls)
package fortik.rules

shl if act.system == "shell"

shl_list(key) := v if {
	v := tgt[key]
	is_array(v)
} else := []

findings contains {
	"rule_id": "POL-501",
	"class": "red",
	"reason": sprintf("database client connects directly to %v, bypassing the Fortik proxy", [object.get(tgt, "db_host", "")]),
	"ladder": "NONE",
} if {
	shl
	tgt.direct_db == true
}

findings contains {
	"rule_id": "POL-502",
	"class": "red",
	"reason": "downloaded or decoded content is piped into a shell or interpreter",
	"ladder": "NONE",
} if {
	shl
	tgt.pipes_to_shell == true
}

shl_red_scopes := {"catastrophic", "remote"}

shl_hold_scopes := {"outside_project", "project_root", "unknown"}

findings contains {
	"rule_id": "POL-503",
	"class": "red",
	"reason": sprintf("destructive %v (%v) on %v", [d.command, d.kind, shl_where(d)]),
	"ladder": "NONE",
} if {
	shl
	some d in shl_list("destructive")
	shl_red_destructive(d)
}

shl_red_destructive(d) if d.scope in shl_red_scopes

shl_red_destructive(d) if d.kind == "disk"

findings contains {
	"rule_id": "POL-503",
	"class": "yellow",
	"reason": sprintf("destructive %v (%v) on %v (%v): approval required", [d.command, d.kind, shl_where(d), d.scope]),
	"hold": true,
} if {
	shl
	some d in shl_list("destructive")
	d.scope in shl_hold_scopes
	not shl_red_destructive(d)
}

shl_where(d) := p if {
	p := d.path
	is_string(p)
	p != ""
} else := "(unresolved target)"

findings contains {
	"rule_id": "POL-504",
	"class": "red",
	"reason": "privilege escalation (sudo/su/doas) refused",
	"ladder": "NONE",
} if {
	shl
	tgt.privilege == true
}

shl_remote_ops := {"remote_copy", "remote_shell"}

shl_egress if {
	tgt.uploads == true
	count(shl_list("external_hosts")) > 0
}

shl_egress if {
	some o in shl_list("operations")
	o in shl_remote_ops
}

shl_egress_secret if tgt.upload_sensitive == true

shl_egress_secret if {
	shl_egress
	count(shl_list("sensitive_reads")) > 0
}

findings contains {
	"rule_id": "POL-505",
	"class": "yellow",
	"reason": sprintf("upload or remote copy/shell to %v: approval required", [shl_list("external_hosts")]),
	"hold": true,
} if {
	shl
	shl_egress
	not shl_egress_secret
}

findings contains {
	"rule_id": "POL-505",
	"class": "red",
	"reason": sprintf("credentials or secrets would leave the machine (to %v)", [shl_list("external_hosts")]),
	"ladder": "NONE",
} if {
	shl
	shl_egress
	shl_egress_secret
}

findings contains {
	"rule_id": "POL-506",
	"class": "yellow",
	"reason": sprintf("command cannot be fully classified (%v): approval required", [concat("; ", shl_list("dynamic_reasons"))]),
	"hold": true,
} if {
	shl
	tgt.dynamic == true
}

findings contains {
	"rule_id": "POL-506",
	"class": "yellow",
	"reason": "shell command without a Fortik classification: approval required",
	"hold": true,
} if {
	shl
	not tgt.classifier == "fortik-shell/1"
}

shl_protected(b) if lower(trim_prefix(b, "refs/heads/")) in {x | some x in cfg.github_protected_branches}

findings contains {
	"rule_id": "POL-507",
	"class": "red",
	"reason": sprintf("git %v on protected branch %v", [g.operation, g.branch]),
	"ladder": "NONE",
} if {
	shl
	some g in shl_list("git")
	g.operation in {"force_push", "delete_branch"}
	shl_protected(g.branch)
}

findings contains {
	"rule_id": "POL-507",
	"class": "yellow",
	"reason": sprintf("git %v on an unresolved branch (%v): approval required", [g.operation, g.branch]),
	"hold": true,
} if {
	shl
	some g in shl_list("git")
	g.operation in {"force_push", "delete_branch"}
	g.branch in {"", "*"}
}

findings contains {
	"rule_id": "POL-507",
	"class": "red",
	"reason": sprintf("GitHub CLI %v on %v", [g.operation, object.get(g, "repo", "")]),
	"ladder": "NONE",
} if {
	shl
	some g in shl_list("gh")
	g.operation in {"delete_repo", "set_secret", "delete_secret", "add_deploy_key", "set_variable"}
}

findings contains {
	"rule_id": "POL-507",
	"class": "yellow",
	"reason": sprintf("GitHub CLI %v: approval required", [g.operation]),
	"hold": true,
} if {
	shl
	some g in shl_list("gh")
	g.operation in {"merge_pr", "run_workflow", "delete_release", "archive_repo", "edit_repo"}
}

# POL-508: the aws CLI, judged with the AWS rule vocabulary.
shl_aws_read_prefixes := ["get", "list", "describe", "head", "lookup", "batchget", "scan", "query", "select"]

shl_aws_op(a) := lower(substring(a, indexof(a, ":") + 1, -1))

shl_aws_read(a) if {
	contains(a, ":")
	some p in shl_aws_read_prefixes
	startswith(shl_aws_op(a), p)
	not lower(a) in {"sts:getfederationtoken", "sts:getsessiontoken"}
}

shl_aws_red(a) if {
	some p in ["iam:", "organizations:", "sso:", "identitystore:", "sts:"]
	startswith(lower(a), p)
	not lower(a) in aws_sts_lookups
}

shl_aws_red(a) if {
	some w in ["delete", "terminate", "remove", "purge", "destroy", "deregister"]
	contains(shl_aws_op(a), w)
}

findings contains {
	"rule_id": "POL-508",
	"class": "red",
	"reason": sprintf("aws CLI %v (identity change or deletion)", [a]),
	"ladder": "NONE",
} if {
	shl
	some a in shl_list("aws_actions")
	is_string(a)
	not shl_aws_read(a)
	shl_aws_red(a)
}

findings contains {
	"rule_id": "POL-508",
	"class": "yellow",
	"reason": sprintf("aws CLI %v changes cloud resources: approval required", [a]),
	"hold": true,
} if {
	shl
	some a in shl_list("aws_actions")
	is_string(a)
	not shl_aws_read(a)
	not shl_aws_red(a)
}
