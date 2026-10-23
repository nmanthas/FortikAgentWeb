# Claude Code hook rules: shell.rego (POL-501..508), files.rego (POL-511,
# POL-512), http.rego and the rule_systems / POL-005 coverage change.
# Targets are what the hook's classifier produces for benign placeholder
# commands; nothing here is executed.
package fortik.tests

import data.fortik.decide

shell_base := {
	"classifier": "fortik-shell/1",
	"commands": [], "operations": [], "external_hosts": [], "external": false,
	"uploads": false, "upload_sensitive": false, "pipes_to_shell": false,
	"direct_db": false, "db_host": "", "dynamic": false, "dynamic_reasons": [],
	"privilege": false, "git": [], "gh": [], "destructive": [], "aws_actions": [],
	"paths": [], "sensitive_writes": [], "sensitive_reads": [],
}

sh(verb, extra) := mk("shell", verb, object.union(shell_base, extra), {}, 0)

dec(inp) := r if {
	r := decide.result with input as inp
}

test_shell_plain_command_allowed if {
	r := dec(sh("READ", {"commands": ["ls"]}))
	r.decision == "allow"
	r2 := dec(sh("EXECUTE", {"commands": ["go"]}))
	r2.decision == "allow"
}

test_shell_without_classifier_held if {
	r := dec(mk("shell", "READ", {"commands": ["ls"]}, {}, 0))
	r.decision == "hold"
	r.rule_id == "POL-506"
	r2 := dec(mk("shell", "EXECUTE", {}, {}, 0))
	r2.decision == "hold"
	r2.rule_id == "POL-005"
}

test_pol501_direct_db_red if {
	r := dec(sh("EXECUTE", {"direct_db": true, "db_host": "db.prod.example.com:5432"}))
	r.class == "red"
	r.decision == "hold"
	r.rule_id == "POL-501"
	not r.ladder_change
}

test_pol501_proxy_allowed if {
	r := dec(sh("EXECUTE", {"direct_db": false, "db_host": "127.0.0.1:6432", "commands": ["psql"]}))
	r.decision == "allow"
}

test_pol502_pipes_to_shell_red if {
	r := dec(sh("EXECUTE", {"pipes_to_shell": true, "external_hosts": ["example.com"], "external": true}))
	r.class == "red"
	r.rule_id == "POL-502"
}

test_pol503_catastrophic_red if {
	r := dec(sh("DELETE", {"destructive": [{"command": "rm", "kind": "filesystem", "scope": "catastrophic", "path": "/"}]}))
	r.class == "red"
	r.rule_id == "POL-503"
}

test_pol503_remote_and_disk_red if {
	r := dec(sh("DELETE", {"destructive": [{"command": "kubectl delete", "kind": "infra", "scope": "remote", "path": ""}]}))
	r.class == "red"
	r.rule_id == "POL-503"
	r2 := dec(sh("DELETE", {"destructive": [{"command": "dd", "kind": "disk", "scope": "project", "path": "/dev/disk9"}]}))
	r2.class == "red"
}

test_pol503_outside_project_held if {
	every sc in ["outside_project", "project_root", "unknown"] {
		r := dec(sh("DELETE", {"destructive": [{"command": "rm", "kind": "filesystem", "scope": sc, "path": "/srv/data"}]}))
		r.class == "yellow"
		r.decision == "hold"
		r.rule_id == "POL-503"
	}
}

test_pol503_inside_project_or_temp_allowed if {
	every sc in ["project", "temp"] {
		r := dec(sh("DELETE", {"destructive": [{"command": "rm", "kind": "filesystem", "scope": sc, "path": "/work/app/build"}]}))
		r.decision == "allow"
	}
}

test_pol504_privilege_red if {
	r := dec(sh("EXECUTE", {"privilege": true, "commands": ["sudo"]}))
	r.class == "red"
	r.rule_id == "POL-504"
}

test_pol505_upload_external_held if {
	r := dec(sh("EXPORT", {"uploads": true, "external_hosts": ["example.com"], "external": true}))
	r.decision == "hold"
	r.class == "yellow"
	r.rule_id == "POL-505"
}

test_pol505_remote_copy_held if {
	r := dec(sh("EXPORT", {"operations": ["remote_copy"], "external_hosts": ["backup.example.com"]}))
	r.decision == "hold"
	r.rule_id == "POL-505"
}

test_pol505_internal_upload_allowed if {
	r := dec(sh("SEND", {"uploads": true, "external_hosts": []}))
	r.decision == "allow"
}

test_pol505_secret_upload_red if {
	r := dec(sh("EXPORT", {"uploads": true, "upload_sensitive": true, "external_hosts": ["example.com"]}))
	r.class == "red"
	r.rule_id == "POL-505"
}

test_pol505_external_get_allowed if {
	r := dec(sh("READ", {"external_hosts": ["example.com"], "external": true}))
	r.decision == "allow"
}

test_pol506_dynamic_held if {
	r := dec(sh("EXECUTE", {"dynamic": true, "dynamic_reasons": ["eval of a non-literal string"]}))
	r.decision == "hold"
	r.rule_id == "POL-506"
	contains(r.reason, "eval")
}

test_pol507_force_push_protected_red if {
	r := dec(sh("WRITE", {"git": [{"operation": "force_push", "remote": "origin", "branch": "main"}]}))
	r.class == "red"
	r.rule_id == "POL-507"
	r2 := dec(sh("WRITE", {"git": [{"operation": "delete_branch", "remote": "origin", "branch": "refs/heads/Production"}]}))
	r2.class == "red"
}

test_pol507_force_push_feature_allowed if {
	r := dec(sh("WRITE", {"git": [{"operation": "force_push", "remote": "origin", "branch": "feature/x"}]}))
	r.decision == "allow"
	r2 := dec(sh("WRITE", {"git": [{"operation": "push", "remote": "origin", "branch": "main"}]}))
	r2.decision == "allow"
}

test_pol507_force_push_unknown_branch_held if {
	r := dec(sh("WRITE", {"git": [{"operation": "force_push", "remote": "origin", "branch": ""}]}))
	r.decision == "hold"
	r.class == "yellow"
	r.rule_id == "POL-507"
}

test_pol507_gh_cli if {
	r := dec(sh("DELETE", {"gh": [{"operation": "delete_repo", "repo": "acme/app"}]}))
	r.class == "red"
	r.rule_id == "POL-507"
	r2 := dec(sh("WRITE", {"gh": [{"operation": "merge_pr", "repo": ""}]}))
	r2.class == "yellow"
	r2.decision == "hold"
	r3 := dec(sh("READ", {"gh": [{"operation": "view_pr", "repo": ""}]}))
	r3.decision == "allow"
}

test_pol508_aws_cli if {
	r := dec(sh("DELETE", {"aws_actions": ["s3:DeleteObject"]}))
	r.class == "red"
	r.rule_id == "POL-508"
	r2 := dec(sh("GRANT", {"aws_actions": ["iam:CreateUser"]}))
	"POL-508" in rule_ids(r2)
	r3 := dec(sh("WRITE", {"aws_actions": ["s3:PutObject"]}))
	r3.class == "yellow"
	r3.rule_id == "POL-508"
	r4 := dec(sh("READ", {"aws_actions": ["s3:ListBucket", "sts:GetCallerIdentity"]}))
	r4.decision == "allow"
	r5 := dec(sh("EXECUTE", {"aws_actions": ["sts:GetSessionToken"]}))
	r5.class == "red"
}

test_pol511_files_sensitive_write_red if {
	r := dec(mk("files", "WRITE", {"path": "/work/app/.env", "sensitive_path": true, "sensitive_kind": "credentials"}, {}, 0))
	r.class == "red"
	r.rule_id == "POL-511"
	r2 := dec(mk("files", "WRITE", {"path": ".github/workflows/ci.yml", "sensitive_path": true, "sensitive_kind": "workflow"}, {}, 0))
	r2.rule_id == "POL-511"
}

test_pol511_files_ordinary_write_allowed if {
	r := dec(mk("files", "WRITE", {"path": "/work/app/main.go", "sensitive_path": false}, {}, 0))
	r.decision == "allow"
}

test_pol511_shell_sensitive_write_red if {
	r := dec(sh("WRITE", {"sensitive_writes": ["/home/dev/.bashrc"], "sensitive_kinds": ["persistence"]}))
	r.class == "red"
	r.rule_id == "POL-511"
}

test_pol512_credential_read_held if {
	r := dec(mk("files", "READ", {"path": "/home/dev/.aws/credentials", "sensitive_path": true, "sensitive_kind": "credentials"}, {}, 0))
	r.decision == "hold"
	r.rule_id == "POL-512"
	r2 := dec(sh("READ", {"sensitive_reads": ["/home/dev/.ssh/id_rsa"]}))
	r2.decision == "hold"
	r2.rule_id == "POL-512"
}

test_pol512_non_credential_sensitive_read_allowed if {
	r := dec(mk("files", "READ", {"path": "/etc/hosts", "sensitive_path": true, "sensitive_kind": "system"}, {}, 0))
	r.decision == "allow"
	r2 := dec(mk("files", "READ", {"path": "README.md", "sensitive_path": false}, {}, 0))
	r2.decision == "allow"
}

test_files_malformed_marker_denied if {
	r := dec(mk("files", "WRITE", {"path": "x", "sensitive_path": "yes"}, {}, 0))
	r.decision == "deny"
	r.rule_id == "POL-009"
}

test_files_uncovered_verb_held if {
	r := dec(mk("files", "DELETE", {"path": "/work/app/x"}, {}, 0))
	r.decision == "hold"
	r.rule_id == "POL-005"
}

test_http_read_allowed if {
	r := dec(mk("http", "READ", {"domain": "example.com", "external": true}, {}, 0))
	r.decision == "allow"
}

test_http_upload_held if {
	every v in ["SEND", "EXPORT", "WRITE"] {
		r := dec(mk("http", v, {"domain": "example.com", "external": true}, {}, 0))
		r.decision == "hold"
		r.rule_id == "POL-505"
	}
}

test_http_uncovered_verb_held if {
	r := dec(mk("http", "DELETE", {"domain": "example.com", "external": true}, {}, 0))
	r.decision == "hold"
	r.rule_id == "POL-005"
}

test_rule_systems_include_phase3 if {
	every s in ["shell", "files", "http", "mcp", "a2a", "agents"] {
		s in data.fortik.rules.rule_systems
	}
}

test_a2a_delegate_allowed_unattended if {
	r := dec(mk("a2a", "DELEGATE", {"to_agent": "agent_1", "channel": "hook_task"}, {}, 0))
	r.decision == "allow"
	not "POL-005" in rule_ids(r)
}

test_a2a_other_verbs_held if {
	r := dec(mk("a2a", "SEND", {"to_agent": "agent_2"}, {}, 0))
	r.decision == "hold"
	r.rule_id == "POL-005"
}

test_agents_spawn_not_held_by_pol005 if {
	r := dec(mk("agents", "DELEGATE", {"operation": "spawn"}, {}, 0))
	not "POL-005" in rule_ids(r)
	r.decision == "allow"
}

test_files_internal_tool_read_allowed if {
	r := dec(mk("files", "READ", {"operation": "internal_tool", "tool": "TodoWrite"}, {}, 0))
	r.decision == "allow"
	r.class == "green"
}

test_memory_still_held_by_pol005 if {
	r := dec(mk("memory", "REMEMBER", {}, {}, 0))
	r.rule_id == "POL-005"
}

test_mcp_tool_call_covered_by_mcp_rules if {
	r := dec(mk("mcp", "WRITE", {"server": "filesystem", "tool": "write_file", "method": "tools/call"}, {}, 0))
	r.decision == "allow"
	r2 := dec(mk("mcp", "WRITE", {"server": "filesystem"}, {}, 0))
	r2.decision == "hold"
	r2.rule_id == "POL-005"
}

test_a2a_task_management_write_covered if {
	r := dec(mk("a2a", "WRITE", {"to_agent": "agent_2", "operation": "tasks/cancel"}, {}, 0))
	r.decision == "allow"
}
