package fortik.tests

import data.fortik.access
import data.fortik.decide

# input.access as Decide builds it (docs/PHASE2_DESIGN.md §5).
with_access(inp, profile) := object.union(inp, {"access": {"system": inp.action.system, "version": 3, "profile": profile}})

no_profile(inp) := object.union(inp, {"access": {"system": inp.action.system, "version": 0, "profile": null}})

denied_by(inp, rule) if {
	r := decide.result with input as inp
	r.decision == "deny"
	r.rule_id == rule
}

not_gated(inp) if {
	not access.gate with input as inp
}

gate_rules(inp) := {d.rule_id | some d in ds} if {
	access.gate with input as inp
	ds := access.denials with input as inp
}

# --- applicability ------------------------------------------------------------

test_gate_absent_without_input_access if {
	not_gated(pg("SELECT", "READ", "prod", {"upstream": "acme_prod"}))
	r := decide.result with input as pg("SELECT", "READ", "prod", {"upstream": "acme_prod"})
	r.decision == "allow"
}

test_gate_ignores_systems_without_profiles if {
	inp := no_profile(mk("memory", "READ", {}, {}, 0))
	not_gated(inp)
	r := decide.result with input as inp
	r.decision == "allow"
}

# Phase 3 (docs/PHASE3_DESIGN.md §1.5): mcp, a2a and http have profiles; no
# profile denies like every other profiled system.
test_gate_denies_mcp_with_null_profile if {
	denied_by(no_profile(mk("mcp", "WRITE", {"server": "memory", "tool": "create_entities"}, {}, 0)), "POL-020")
}

test_no_profile_denies_every_profiled_system if {
	every sys in ["gmail", "drive", "github", "aws", "postgres"] {
		denied_by(no_profile(mk(sys, "READ", {}, {}, 0)), "POL-020")
	}
}

test_no_profile_reason_names_system if {
	r := decide.result with input as no_profile(mk("aws", "READ", {"iam_action": "s3:GetObject"}, {}, 0))
	r.reason == "no access profile for aws: access denied by default"
	r.class == "green"
}

test_non_object_profile_treated_as_none if {
	inp := object.union(mk("drive", "READ", {}, {}, 0), {"access": {"system": "drive", "version": 1, "profile": "read_write"}})
	denied_by(inp, "POL-020")
}

test_profile_for_other_system_denied if {
	inp := object.union(mk("drive", "READ", {}, {}, 0), {"access": {"system": "gmail", "version": 2, "profile": {"mode": "read_write", "share": "any"}}})
	denied_by(inp, "POL-020")
}

test_access_missing_system_key_denied if {
	inp := object.union(mk("drive", "READ", {}, {}, 0), {"access": {"version": 2, "profile": {"mode": "read_write", "share": "any"}}})
	denied_by(inp, "POL-020")
}

# --- control gate wins over the access gate ------------------------------------

test_control_gate_checked_first if {
	inp := no_profile(with_level(pg("INSERT", "WRITE", "prod", {"upstream": "acme_prod"}), 2))
	denied_by(inp, "POL-013")
}

test_unregistered_beats_missing_profile if {
	base := no_profile(pg("SELECT", "READ", "prod", {"upstream": "acme_prod"}))
	inp := object.union(base, {"agent": {"agent_id": "ghost", "registered": false, "level": 0}})
	denied_by(inp, "POL-015")
}

test_access_gate_keeps_red_class_and_ladder if {
	# A red action without access is refused by the access gate; the red
	# finding's own step-down still applies (the gate adds none).
	inp := with_access(pg("DROP_TABLE", "DELETE", "prod", {"upstream": "acme_prod"}), {"upstreams": {"acme_prod": "read_only"}})
	r := decide.result with input as inp
	r.decision == "deny"
	r.rule_id == "POL-026"
	r.class == "red"
	r.ladder_change.to == "READ_ONLY"
}

test_access_gate_never_adds_ladder_on_green if {
	r := decide.result with input as no_profile(pg("SELECT", "READ", "prod", {"upstream": "acme_prod"}))
	r.decision == "deny"
	not r.ladder_change
	not r.reduced_form
}

test_allowed_by_profile_falls_through_to_rules if {
	inp := with_access(pg("DELETE", "DELETE", "staging", {"upstream": "acme_staging", "undo_preparable": true}), {"upstreams": {"acme_staging": "read_write"}})
	r := decide.result with input as inp
	r.decision == "allow_reduced"
	r.rule_id == "POL-102"
}

# --- Postgres ------------------------------------------------------------------

pg_profile := {"upstreams": {"acme_prod": "read_only", "acme_staging": "read_write", "legacy": "none"}}

test_pg_read_on_read_only_upstream_allowed if {
	inp := with_access(pg("SELECT", "READ", "prod", {"upstream": "acme_prod"}), pg_profile)
	not_gated(inp)
	r := decide.result with input as inp
	r.decision == "allow"
}

test_pg_write_on_read_only_upstream_denied if {
	denied_by(with_access(pg("INSERT", "WRITE", "prod", {"upstream": "acme_prod", "on_conflict_update": false}), pg_profile), "POL-026")
}

test_pg_export_on_read_only_upstream_denied if {
	denied_by(with_access(pg("COPY_TO", "EXPORT", "prod", {"upstream": "acme_prod"}), pg_profile), "POL-026")
}

test_pg_write_on_read_write_upstream_allowed if {
	inp := with_access(pg("INSERT", "WRITE", "staging", {"upstream": "acme_staging", "on_conflict_update": false}), pg_profile)
	not_gated(inp)
}

test_pg_upstream_none_is_pol020 if {
	denied_by(with_access(pg("SELECT", "READ", "dev", {"upstream": "legacy"}), pg_profile), "POL-020")
}

test_pg_unknown_upstream_denied if {
	denied_by(with_access(pg("SELECT", "READ", "prod", {"upstream": "other_db"}), pg_profile), "POL-026")
}

test_pg_missing_upstream_denied if {
	inp := with_access(pg("SELECT", "READ", "prod", {}), pg_profile)
	denied_by(inp, "POL-026")
	r := decide.result with input as inp
	contains(r.reason, "names no upstream")
}

test_pg_non_string_upstream_denied if {
	denied_by(with_access(pg("SELECT", "READ", "prod", {"upstream": 7}), pg_profile), "POL-026")
}

test_pg_unknown_mode_value_denied if {
	denied_by(with_access(pg("SELECT", "READ", "prod", {"upstream": "acme_prod"}), {"upstreams": {"acme_prod": "rw"}}), "POL-020")
}

test_pg_non_object_upstreams_denied if {
	denied_by(with_access(pg("SELECT", "READ", "prod", {"upstream": "acme_prod"}), {"upstreams": ["acme_prod"]}), "POL-026")
}

test_pg_empty_profile_denied if {
	denied_by(with_access(pg("SELECT", "READ", "prod", {"upstream": "acme_prod"}), {"upstreams": {}}), "POL-026")
}

test_pg_reason_mentions_version if {
	r := decide.result with input as with_access(pg("INSERT", "WRITE", "prod", {"upstream": "acme_prod"}), pg_profile)
	r.reason == "access profile v3 for postgres: upstream acme_prod is read_only: WRITE refused"
}

# --- Gmail ---------------------------------------------------------------------

gmail_internal := {"send": "internal_only", "read": true, "max_recipients": 10}

gmail_any := {"send": "any", "read": true, "max_recipients": 25}

test_gmail_read_allowed if {
	not_gated(with_access(mk("gmail", "READ", {}, {}, 0), gmail_internal))
}

test_gmail_read_not_granted if {
	denied_by(with_access(mk("gmail", "READ", {}, {}, 0), {"send": "any", "read": false, "max_recipients": 5}), "POL-020")
}

test_gmail_read_missing_flag_denied if {
	denied_by(with_access(mk("gmail", "READ", {}, {}, 0), {"send": "any", "max_recipients": 5}), "POL-020")
}

test_gmail_send_none_denied if {
	denied_by(with_access(mk("gmail", "SEND", {"external_domains": 0}, {"recipients": 1}, 0), {"send": "none", "read": true, "max_recipients": 5}), "POL-020")
}

test_gmail_mailbox_change_needs_send if {
	denied_by(with_access(mk("gmail", "WRITE", {}, {}, 0), {"send": "none", "read": true, "max_recipients": 5}), "POL-020")
}

test_gmail_unknown_send_value_denied if {
	denied_by(with_access(mk("gmail", "SEND", {"external_domains": 0}, {"recipients": 1}, 0), {"send": "everyone", "read": true, "max_recipients": 5}), "POL-020")
}

test_gmail_internal_send_allowed_internal_only if {
	inp := with_access(mk("gmail", "SEND", {"external_domains": 0}, {"recipients": 3}, 0), gmail_internal)
	not_gated(inp)
	r := decide.result with input as inp
	r.decision == "allow"
}

test_gmail_external_send_denied_internal_only if {
	denied_by(with_access(mk("gmail", "SEND", {"external_domains": 1}, {"recipients": 1}, 0), gmail_internal), "POL-022")
}

test_gmail_external_flag_denied_internal_only if {
	denied_by(with_access(mk("gmail", "SEND", {"external": true}, {"recipients": 1}, 0), gmail_internal), "POL-022")
}

test_gmail_malformed_external_counts_as_external if {
	"POL-022" in gate_rules(with_access(mk("gmail", "SEND", {"external": "yes"}, {"recipients": 1}, 0), gmail_internal))
	"POL-022" in gate_rules(with_access(mk("gmail", "SEND", {"external_domains": "1"}, {"recipients": 1}, 0), gmail_internal))
}

test_gmail_external_send_any_reaches_delay_rule if {
	inp := with_access(mk("gmail", "SEND", {"external_domains": 1}, {"recipients": 1}, 0), gmail_any)
	not_gated(inp)
	r := decide.result with input as inp
	r.decision == "allow_reduced"
	r.rule_id == "POL-202"
}

test_gmail_recipients_over_max_denied if {
	denied_by(with_access(mk("gmail", "SEND", {"external_domains": 0}, {"recipients": 11}, 0), gmail_internal), "POL-027")
}

test_gmail_recipients_at_max_allowed if {
	not_gated(with_access(mk("gmail", "SEND", {"external_domains": 0}, {"recipients": 10}, 0), gmail_internal))
}

test_gmail_missing_max_means_zero if {
	denied_by(with_access(mk("gmail", "SEND", {"external_domains": 0}, {"recipients": 1}, 0), {"send": "any", "read": true}), "POL-027")
}

test_gmail_malformed_recipients_denied if {
	denied_by(with_access(mk("gmail", "SEND", {"external_domains": 0}, {"recipients": "5"}, 0), gmail_any), "POL-027")
}

test_gmail_external_and_over_max_reports_lowest_rule if {
	inp := with_access(mk("gmail", "SEND", {"external_domains": 2}, {"recipients": 50}, 0), gmail_internal)
	gate_rules(inp) == {"POL-022", "POL-027"}
	denied_by(inp, "POL-022")
}

# --- Drive ---------------------------------------------------------------------

drive_rw_internal := {"mode": "read_write", "share": "internal_only"}

test_drive_mode_none_denied if {
	denied_by(with_access(mk("drive", "READ", {}, {}, 0), {"mode": "none", "share": "none"}), "POL-020")
}

test_drive_unknown_mode_denied if {
	denied_by(with_access(mk("drive", "READ", {}, {}, 0), {"mode": "admin", "share": "none"}), "POL-020")
}

test_drive_read_only_read_allowed if {
	not_gated(with_access(mk("drive", "READ", {}, {}, 0), {"mode": "read_only", "share": "none"}))
}

test_drive_read_only_write_denied if {
	denied_by(with_access(mk("drive", "WRITE", {}, {}, 0), {"mode": "read_only", "share": "any"}), "POL-021")
}

test_drive_read_write_write_allowed if {
	not_gated(with_access(mk("drive", "WRITE", {}, {}, 0), drive_rw_internal))
}

test_drive_internal_share_allowed_internal_only if {
	inp := with_access(mk("drive", "EXPORT", {"operation": "share", "share_type": "user", "external": false}, {}, 0), drive_rw_internal)
	not_gated(inp)
}

test_drive_external_share_denied_internal_only if {
	denied_by(with_access(mk("drive", "EXPORT", {"operation": "share", "share_type": "user", "external": true}, {}, 0), drive_rw_internal), "POL-023")
}

test_drive_anyone_share_denied_internal_only if {
	denied_by(with_access(mk("drive", "EXPORT", {"operation": "share", "share_type": "anyone"}, {}, 0), drive_rw_internal), "POL-023")
}

test_drive_share_type_case_insensitive if {
	denied_by(with_access(mk("drive", "EXPORT", {"operation": "Share", "share_type": "Anyone"}, {}, 0), drive_rw_internal), "POL-023")
}

test_drive_share_none_denies_any_share if {
	denied_by(with_access(mk("drive", "EXPORT", {"operation": "share", "share_type": "user", "external": false}, {}, 0), {"mode": "read_write", "share": "none"}), "POL-023")
}

test_drive_share_none_denies_share_by_other_verb if {
	denied_by(with_access(mk("drive", "GRANT", {"operation": "share", "share_type": "user"}, {}, 0), {"mode": "read_write", "share": "none"}), "POL-023")
}

test_drive_share_missing_value_denied if {
	denied_by(with_access(mk("drive", "EXPORT", {"operation": "share", "share_type": "user"}, {}, 0), {"mode": "read_write"}), "POL-023")
}

test_drive_share_any_reaches_narrowing_rule if {
	inp := with_access(mk("drive", "EXPORT", {"operation": "share", "share_type": "anyone"}, {}, 0), {"mode": "read_write", "share": "any"})
	not_gated(inp)
	r := decide.result with input as inp
	r.decision == "allow_reduced"
	r.rule_id == "POL-211"
}

test_drive_share_read_only_reports_pol021_first if {
	inp := with_access(mk("drive", "EXPORT", {"operation": "share", "share_type": "anyone"}, {}, 0), {"mode": "read_only", "share": "internal_only"})
	gate_rules(inp) == {"POL-021", "POL-023"}
	denied_by(inp, "POL-021")
}

# --- GitHub --------------------------------------------------------------------

gh_profile := {
	"repos": ["acme/api", "acme/web"],
	"permissions": {"contents": "write", "pull_requests": "read", "issues": "read", "metadata": "read"},
	"allow_direct_token": false,
}

gh_pr_writer := {
	"repos": ["acme/api"],
	"permissions": {"contents": "read", "pull_requests": "write", "metadata": "read"},
	"allow_direct_token": true,
}

gh(verb, op, extra) := mk("github", verb, object.union({"repo": "acme/api", "branch": "feature/x", "operation": op}, extra), {}, 0)

test_gh_read_in_repo_allowed if {
	not_gated(with_access(gh("READ", "get_contents", {}), gh_profile))
}

test_gh_repo_case_insensitive if {
	not_gated(with_access(gh("READ", "get_contents", {"repo": "ACME/Api"}), gh_profile))
}

test_gh_repo_not_in_profile_denied if {
	denied_by(with_access(gh("READ", "get_contents", {"repo": "acme/secret"}), gh_profile), "POL-024")
}

test_gh_no_repo_denied if {
	inp := with_access(mk("github", "READ", {"operation": "list_user"}, {}, 0), gh_profile)
	denied_by(inp, "POL-024")
}

test_gh_contents_write_ops_allowed_with_contents_write if {
	every op in ["push", "force_push", "delete_branch"] {
		not_gated(with_access(gh("WRITE", op, {}), gh_profile))
	}
}

test_gh_contents_write_ops_need_contents_write if {
	every op in ["push", "force_push", "delete_branch", "merge_pr"] {
		inp := with_access(gh("WRITE", op, {}), gh_pr_writer)
		"POL-024" in gate_rules(inp)
		denied_by(inp, "POL-024")
	}
}

test_gh_edit_paths_need_contents_write if {
	inp := with_access(gh("WRITE", "update_pr", {"paths": ["src/main.go"]}), gh_pr_writer)
	denied_by(inp, "POL-024")
	r := decide.result with input as inp
	contains(r.reason, "contents:write")
}

test_gh_pr_ops_need_pull_requests_write if {
	every op in ["create_pr", "close_pr", "merge_pr"] {
		inp := with_access(gh("WRITE", op, {}), gh_profile)
		denied_by(inp, "POL-024")
		r := decide.result with input as inp
		contains(r.reason, "pull_requests:write")
	}
}

test_gh_pr_ops_allowed_with_pull_requests_write if {
	every op in ["create_pr", "close_pr"] {
		not_gated(with_access(gh("WRITE", op, {}), gh_pr_writer))
	}
}

test_gh_merge_pr_needs_both if {
	both := object.union(gh_profile, {"permissions": {"contents": "write", "pull_requests": "write"}})
	not_gated(with_access(gh("WRITE", "merge_pr", {"branch": "feature/x"}), both))
}

test_gh_issue_ops_need_issues_write if {
	denied_by(with_access(gh("WRITE", "create_issue", {}), gh_profile), "POL-024")
	writer := object.union(gh_profile, {"permissions": {"issues": "write"}})
	not_gated(with_access(gh("WRITE", "create_issue", {}), writer))
}

test_gh_unmapped_write_needs_contents_write if {
	denied_by(with_access(gh("WRITE", "create_release", {}), gh_pr_writer), "POL-024")
	not_gated(with_access(gh("WRITE", "create_release", {}), gh_profile))
}

test_gh_missing_permissions_object_denies_writes if {
	denied_by(with_access(gh("WRITE", "push", {}), {"repos": ["acme/api"]}), "POL-024")
}

test_gh_direct_token_needs_allow_direct_token if {
	cred := mk("github", "READ", {"repos": ["acme/api"], "permissions": {"contents": "read"}, "operation": "credential", "credential_request": true}, {}, 0)
	denied_by(with_access(cred, gh_profile), "POL-024")
	not_gated(with_access(cred, object.union(gh_profile, {"allow_direct_token": true})))
}

test_gh_direct_token_permission_within_profile if {
	cred := mk("github", "WRITE", {"repos": ["acme/api"], "permissions": {"contents": "read", "pull_requests": "write"}, "operation": "credential", "credential_request": true}, {}, 0)
	not_gated(with_access(cred, gh_pr_writer))
}

test_gh_direct_token_permission_exceeds_profile if {
	cred := mk("github", "WRITE", {"repos": ["acme/api"], "permissions": {"contents": "write"}, "operation": "credential", "credential_request": true}, {}, 0)
	inp := with_access(cred, gh_pr_writer)
	denied_by(inp, "POL-024")
	r := decide.result with input as inp
	contains(r.reason, "contents:write exceeds the profile")
}

test_gh_direct_token_unknown_permission_denied if {
	cred := mk("github", "WRITE", {"repos": ["acme/api"], "permissions": {"administration": "write"}, "operation": "credential", "credential_request": true}, {}, 0)
	denied_by(with_access(cred, gh_pr_writer), "POL-024")
}

test_gh_direct_token_bad_level_denied if {
	cred := mk("github", "READ", {"repos": ["acme/api"], "permissions": {"contents": "admin"}, "operation": "credential", "credential_request": true}, {}, 0)
	denied_by(with_access(cred, gh_pr_writer), "POL-024")
}

test_gh_direct_token_every_repo_must_be_in_profile if {
	cred := mk("github", "READ", {"repos": ["acme/api", "acme/infra"], "permissions": {"contents": "read"}, "operation": "credential", "credential_request": true}, {}, 0)
	denied_by(with_access(cred, gh_pr_writer), "POL-024")
}

test_gh_direct_token_needs_repos_and_permissions if {
	no_repos := mk("github", "READ", {"repos": [], "permissions": {"contents": "read"}, "operation": "credential", "credential_request": true}, {}, 0)
	denied_by(with_access(no_repos, gh_pr_writer), "POL-024")
	no_perms := mk("github", "READ", {"repos": ["acme/api"], "permissions": {}, "operation": "credential", "credential_request": true}, {}, 0)
	denied_by(with_access(no_perms, gh_pr_writer), "POL-024")
}

test_gh_protected_branch_red_rule_still_applies_when_allowed if {
	inp := with_access(gh("WRITE", "force_push", {"branch": "main"}), gh_profile)
	not_gated(inp)
	r := decide.result with input as inp
	r.rule_id == "POL-301"
	r.decision == "hold"
}

# --- AWS -----------------------------------------------------------------------

aws_profile := {"mode": "read_write", "services": ["s3", "ec2"], "denied_actions": ["iam:*", "s3:delete*", "ec2:terminate?nstances"]}

aws_act(verb, iam_action) := mk("aws", verb, {"iam_action": iam_action, "resource": "arn:aws:s3:::reports/*", "credential_request": true}, {}, 0)

test_aws_allowed_service_and_action if {
	inp := with_access(aws_act("READ", "s3:GetObject"), aws_profile)
	not_gated(inp)
	r := decide.result with input as inp
	r.decision == "allow"
}

test_aws_mode_none_denied if {
	denied_by(with_access(aws_act("READ", "s3:GetObject"), {"mode": "none", "services": ["s3"], "denied_actions": []}), "POL-020")
}

test_aws_read_only_denies_write if {
	denied_by(with_access(aws_act("WRITE", "s3:PutObject"), {"mode": "read_only", "services": ["s3"], "denied_actions": []}), "POL-021")
}

test_aws_read_only_allows_read if {
	not_gated(with_access(aws_act("READ", "s3:ListBucket"), {"mode": "read_only", "services": ["s3"], "denied_actions": []}))
}

test_aws_service_not_in_profile if {
	inp := with_access(aws_act("READ", "dynamodb:GetItem"), aws_profile)
	denied_by(inp, "POL-025")
	r := decide.result with input as inp
	contains(r.reason, "service dynamodb is not in the profile")
}

test_aws_service_case_insensitive if {
	not_gated(with_access(aws_act("READ", "S3:GetObject"), aws_profile))
}

test_aws_denied_actions_glob_star if {
	inp := with_access(aws_act("WRITE", "s3:DeleteObject"), aws_profile)
	denied_by(inp, "POL-025")
	r := decide.result with input as inp
	contains(r.reason, "matches denied action s3:delete*")
}

test_aws_denied_actions_glob_question_mark if {
	denied_by(with_access(aws_act("DELETE", "ec2:TerminateInstances"), aws_profile), "POL-025")
}

test_aws_denied_actions_service_wide if {
	p := object.union(aws_profile, {"services": ["s3", "ec2", "iam"]})
	denied_by(with_access(aws_act("READ", "iam:GetUser"), p), "POL-025")
}

test_aws_denied_actions_star_denies_everything if {
	denied_by(with_access(aws_act("READ", "s3:GetObject"), {"mode": "read_write", "services": ["s3"], "denied_actions": ["*"]}), "POL-025")
}

test_aws_denied_pattern_does_not_overmatch if {
	not_gated(with_access(aws_act("WRITE", "s3:PutObject"), aws_profile))
}

test_aws_missing_iam_action_denied if {
	denied_by(with_access(mk("aws", "READ", {"resource": "*"}, {}, 0), aws_profile), "POL-025")
}

test_aws_malformed_iam_action_denied if {
	denied_by(with_access(aws_act("READ", "s3GetObject"), aws_profile), "POL-025")
	denied_by(with_access(aws_act("READ", "s3:"), aws_profile), "POL-025")
	denied_by(with_access(aws_act("READ", ":GetObject"), aws_profile), "POL-025")
}

test_aws_missing_services_denied if {
	denied_by(with_access(aws_act("READ", "s3:GetObject"), {"mode": "read_write"}), "POL-025")
}

test_aws_spend_rule_still_applies_when_allowed if {
	inp := object.union(with_access(aws_act("SPEND", "ec2:RunInstances"), aws_profile), {"action": object.union(aws_act("SPEND", "ec2:RunInstances").action, {"est_cost_usd": 900})})
	not_gated(inp)
	r := decide.result with input as inp
	r.rule_id == "POL-403"
	r.decision == "hold"
}

# --- determinism -----------------------------------------------------------------

test_gate_pick_is_lowest_rule if {
	inp := with_access(aws_act("WRITE", "dynamodb:DeleteTable"), {"mode": "read_only", "services": ["s3"], "denied_actions": ["dynamodb:*"]})
	gate_rules(inp) == {"POL-021", "POL-025"}
	denied_by(inp, "POL-021")
}

test_gh_read_with_paths_needs_no_write if {
	not_gated(with_access(gh("READ", "read", {"paths": ["src/main.go"]}), gh_pr_writer))
}

test_gh_pr_comment_needs_pull_requests_write if {
	inp := gh("WRITE", "comment", {"endpoint": "/repos/{owner}/{repo}/pulls/{number}/comments"})
	denied_by(with_access(inp, gh_profile), "POL-024")
	r := decide.result with input as with_access(inp, gh_profile)
	contains(r.reason, "pull_requests:write")
	not_gated(with_access(inp, gh_pr_writer))
}

test_gh_issue_comment_needs_issues_write if {
	inp := gh("WRITE", "comment", {"endpoint": "/repos/{owner}/{repo}/issues/{number}/comments"})
	denied_by(with_access(inp, gh_pr_writer), "POL-024")
	r := decide.result with input as with_access(inp, gh_pr_writer)
	contains(r.reason, "issues:write")
	writer := object.union(gh_profile, {"permissions": {"issues": "write"}})
	not_gated(with_access(inp, writer))
}
