# A shell command that reaches another system (target.reaches, set by the
# hook's classifier: github for gh and git remote operations, aws for the AWS
# CLI) is covered by that system's timed suspensions (POL-030 / POL-031).
package fortik.tests

import data.fortik.decide

gh_view := sh("READ", {"commands": ["gh"], "reaches": ["github"]})

git_push := sh("WRITE", {"commands": ["git"], "git": [{"operation": "push", "op": "push", "remote": "origin", "branch": "feature/x", "force": false}], "reaches": ["github"]})

over(system, mode) := {"overrides": {"active": [{"override_id": "ovr_1", "system": system, "mode": mode, "status": "active", "expires_at": "2099-01-01T00:00:00Z"}]}}

with_ctx(inp, c) := object.union(inp, {"context": c})

test_shell_reaching_github_allowed_without_suspension if {
	decide.result.decision == "allow" with input as gh_view
	decide.result.decision == "allow" with input as git_push
}

test_github_suspension_covers_gh_and_git_push if {
	r := decide.result with input as with_ctx(gh_view, over("github", "suspended"))
	r.decision == "deny"
	r.rule_id == "POL-030"
	p := decide.result with input as with_ctx(git_push, over("github", "suspended"))
	p.decision == "deny"
	p.rule_id == "POL-030"
}

test_github_read_only_override_allows_view_refuses_push if {
	r := decide.result with input as with_ctx(gh_view, over("github", "read_only"))
	r.decision == "allow"
	p := decide.result with input as with_ctx(git_push, over("github", "read_only"))
	p.decision == "deny"
	p.rule_id == "POL-031"
}

# A suspension of an unrelated system does not touch the command, and a
# command that reaches nothing is not covered by a GitHub suspension.
test_unrelated_suspension_and_local_command if {
	r := decide.result with input as with_ctx(gh_view, over("drive", "suspended"))
	r.decision == "allow"
	l := decide.result with input as with_ctx(sh("READ", {"commands": ["ls"]}), over("github", "suspended"))
	l.decision == "allow"
}

test_aws_cli_covered_by_aws_suspension if {
	a := sh("READ", {"commands": ["aws"], "aws_actions": ["s3:ListBucket"], "external_hosts": ["amazonaws.com"], "external": true, "reaches": ["aws"]})
	r := decide.result with input as with_ctx(a, over("aws", "suspended"))
	r.decision == "deny"
	r.rule_id == "POL-030"
}

# The refusal names the suspended system (github), not the shell.
test_suspension_reason_names_the_suspended_system if {
	r := decide.result with input as with_ctx(gh_view, over("github", "suspended"))
	startswith(r.reason, "github suspended")
}
