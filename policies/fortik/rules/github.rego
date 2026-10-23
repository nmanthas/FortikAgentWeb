# GitHub rules. Adapter contract (Phase 2 app gateway):
#   target.repo, target.branch, target.operation in
#   {"push","force_push","delete_branch","close_pr","merge_pr","create_pr",
#    "set_secret","create_webhook","add_deploy_key","edit_workflow"},
#   target.paths (changed paths, when known).
package fortik.rules

gh if act.system == "github"

gh_op := lower(object.get(tgt, "operation", ""))

# Normalise "refs/heads/Main" -> "main" so a ref spelling cannot dodge the
# protected-branch rules.
gh_branch := lower(trim_prefix(object.get(tgt, "branch", ""), "refs/heads/"))

gh_protected if gh_branch in {b | some b in cfg.github_protected_branches}

gh_protected if tgt.protected == true

gh_adjacent if {
	some p in cfg.github_protected_adjacent_prefixes
	startswith(gh_branch, p)
}

# POL-301: rewriting or deleting a protected branch is irreversible for others.
findings contains {
	"rule_id": "POL-301",
	"class": "red",
	"reason": sprintf("%s on protected branch %s of %v", [gh_op, gh_branch, object.get(tgt, "repo", "")]),
	"ladder": "ISOLATED",
} if {
	gh
	gh_protected
	gh_op in {"force_push", "delete_branch"}
}

# POL-302: risky but reversible ref changes record the previous sha first.
findings contains {
	"rule_id": "POL-302",
	"class": "yellow",
	"reason": sprintf("%s on %s: previous ref recorded for undo", [gh_op, gh_branch]),
	"reduced_form": {"record_ref": true},
} if {
	gh
	gh_adjacent
	not gh_protected
	gh_op in {"push", "force_push"}
}

findings contains {
	"rule_id": "POL-302",
	"class": "yellow",
	"reason": sprintf("%s: previous ref/state recorded for undo", [gh_op]),
	"reduced_form": {"record_ref": true},
} if {
	gh
	not gh_protected
	gh_op in {"delete_branch", "close_pr"}
}

# POL-303: CI/CD and credential surfaces (workflows, secrets, webhooks,
# deploy keys) are supply-chain risks.
gh_workflow_path if {
	some p in object.get(tgt, "paths", [])
	startswith(p, ".github/workflows/")
}

findings contains {
	"rule_id": "POL-303",
	"class": "red",
	"reason": sprintf("GitHub supply-chain surface change (%s)", [gh_op]),
	"ladder": "ISOLATED",
} if {
	gh
	gh_op in {"set_secret", "create_webhook", "add_deploy_key", "edit_workflow"}
}

findings contains {
	"rule_id": "POL-303",
	"class": "red",
	"reason": "GitHub supply-chain surface change (.github/workflows modified)",
	"ladder": "ISOLATED",
} if {
	gh
	gh_workflow_path
}

# POL-302 (protected branches): ordinary pushes and merges to a protected
# branch are reversible only if the previous ref is recorded first.
findings contains {
	"rule_id": "POL-302",
	"class": "yellow",
	"reason": sprintf("%s to protected branch %s: previous ref recorded for undo", [gh_op, gh_branch]),
	"reduced_form": {"record_ref": true},
} if {
	gh
	gh_protected
	gh_op in {"push", "merge_pr"}
}

# POL-304: other GitHub deletions (repositories, releases, tags, environments)
# are irreversible.
findings contains {
	"rule_id": "POL-304",
	"class": "red",
	"reason": sprintf("irreversible GitHub deletion (%v) on %v", [gh_op, object.get(tgt, "repo", "")]),
	"ladder": "ISOLATED",
} if {
	gh
	act.verb == "DELETE"
	not gh_op in {"delete_branch", "close_pr"}
}

# POL-304 by operation name, whatever verb the adapter used.
findings contains {
	"rule_id": "POL-304",
	"class": "red",
	"reason": sprintf("irreversible GitHub deletion (%v) on %v", [gh_op, object.get(tgt, "repo", "")]),
	"ladder": "ISOLATED",
} if {
	gh
	startswith(gh_op, "delete_")
	gh_op != "delete_branch"
}

# POL-305: dispatching a workflow runs CI (with repository secrets) on code the
# agent may have pushed itself: approval required.
findings contains {
	"rule_id": "POL-305",
	"class": "yellow",
	"reason": sprintf("workflow dispatch on %v runs CI with repository secrets: approval required", [object.get(tgt, "repo", "")]),
	"hold": true,
} if {
	gh
	gh_op == "run_workflow"
}
