package fortik.tests

import data.fortik.decide

# --- Gmail ---------------------------------------------------------------

test_internal_email_green if {
	r := decide.result with input as mk("gmail", "SEND", {"to": ["bob@acme.com"], "external_domains": 0}, {"recipients": 1}, 0)
	r.class == "green"
	r.decision == "allow"
}

test_external_email_delayed if {
	r := decide.result with input as mk("gmail", "SEND", {"to": ["x@other.com"], "external_domains": 1}, {"recipients": 1}, 0)
	r.class == "yellow"
	r.decision == "allow_reduced"
	r.rule_id == "POL-202"
	r.reduced_form.delay_send_seconds == 120
}

test_customer_data_to_external_domain_red if {
	r := decide.result with input as mk(
		"gmail", "SEND",
		{"to": ["investor@venturefund.com"], "external_domains": 1},
		{"attachments": 1, "bytes": 12582912, "data_labels": ["customer_pii"], "recipients": 1}, 0,
	)
	r.class == "red"
	r.decision == "hold"
	r.rule_id == "POL-201"
	r.ladder_change.to == "ISOLATED"
}

test_bulk_email_held_even_if_external_delay_possible if {
	r := decide.result with input as mk("gmail", "SEND", {"external_domains": 48}, {"recipients": 48}, 0)
	r.class == "yellow"
	r.decision == "hold"

	# The bulk finding demands the hold, so it is the reported rule; the
	# delayed-send finding is still recorded.
	r.rule_id == "POL-203"
	"POL-202" in rule_ids(r)
}

test_bulk_internal_email_held if {
	r := decide.result with input as mk("gmail", "SEND", {"external_domains": 0}, {"recipients": 200}, 0)
	r.decision == "hold"
	r.rule_id == "POL-203"
}

# --- Drive ---------------------------------------------------------------

test_drive_public_link_narrowed if {
	r := decide.result with input as mk("drive", "EXPORT", {"operation": "share", "share_type": "anyone"}, {"data_labels": ["customer_pii"]}, 0)
	r.class == "yellow"
	r.decision == "allow_reduced"
	r.rule_id == "POL-211"
	r.reduced_form.narrow_share == "domain"
	r.reduced_form.record_permission == true
}

test_drive_external_share_non_sensitive_narrowed if {
	r := decide.result with input as mk("drive", "EXPORT", {"operation": "share", "share_type": "user", "external": true}, {}, 0)
	r.rule_id == "POL-211"
	r.decision == "allow_reduced"
}

test_drive_external_share_sensitive_red if {
	r := decide.result with input as mk("drive", "EXPORT", {"operation": "share", "share_type": "user", "external": true}, {"data_labels": ["customer_pii"]}, 0)
	r.class == "red"
	r.rule_id == "POL-212"
}

test_drive_external_share_without_share_type_sensitive_red if {
	r := decide.result with input as mk("drive", "EXPORT", {"operation": "share", "external": true}, {"data_labels": ["financial"]}, 0)
	r.class == "red"
	r.rule_id == "POL-212"
}

test_drive_internal_share_green if {
	r := decide.result with input as mk("drive", "EXPORT", {"operation": "share", "share_type": "user", "external": false}, {}, 0)
	r.class == "green"
}

# --- GitHub --------------------------------------------------------------

test_push_feature_branch_green if {
	r := decide.result with input as mk("github", "WRITE", {"repo": "acme/api", "branch": "feat/x", "operation": "push"}, {}, 0)
	r.class == "green"
	r.decision == "allow"
}

test_force_push_main_red if {
	r := decide.result with input as mk("github", "WRITE", {"repo": "acme/api", "branch": "main", "operation": "force_push"}, {}, 0)
	r.class == "red"
	r.rule_id == "POL-301"
}

test_delete_protected_flag_branch_red if {
	r := decide.result with input as mk("github", "DELETE", {"branch": "env/eu", "protected": true, "operation": "delete_branch"}, {}, 0)
	r.rule_id == "POL-301"
}

test_push_release_branch_records_ref if {
	r := decide.result with input as mk("github", "WRITE", {"branch": "release/2.4", "operation": "push"}, {}, 0)
	r.class == "yellow"
	r.decision == "allow_reduced"
	r.rule_id == "POL-302"
	r.reduced_form.record_ref == true
}

test_delete_feature_branch_and_close_pr_record_ref if {
	every op in ["delete_branch", "close_pr"] {
		r := decide.result with input as mk("github", "DELETE", {"branch": "feat/y", "operation": op}, {}, 0)
		r.rule_id == "POL-302"
		r.decision == "allow_reduced"
	}
}

test_workflow_and_secret_changes_red if {
	every op in ["set_secret", "create_webhook", "add_deploy_key", "edit_workflow"] {
		r := decide.result with input as mk("github", "WRITE", {"branch": "feat/z", "operation": op}, {}, 0)
		r.class == "red"
		r.rule_id == "POL-303"
	}
}

test_push_touching_workflows_red if {
	r := decide.result with input as mk("github", "WRITE", {"branch": "feat/z", "operation": "push", "paths": ["src/a.go", ".github/workflows/ci.yml"]}, {}, 0)
	r.rule_id == "POL-303"
}

# --- AWS -----------------------------------------------------------------

test_aws_describe_green if {
	r := decide.result with input as mk("aws", "READ", {"iam_action": "ec2:DescribeInstances"}, {}, 0)
	r.class == "green"
}

test_aws_sts_credential_minting_red if {
	every a in ["sts:AssumeRole", "sts:AssumeRoleWithWebIdentity", "sts:AssumeRoleWithSAML", "sts:GetFederationToken", "sts:GetSessionToken", "sts:TagSession", "sts:SetSourceIdentity"] {
		r := decide.result with input as mk("aws", "EXECUTE", {"iam_action": a, "resource": "*", "credential_request": true}, {}, 0)
		r.class == "red"
		r.rule_id == "POL-401"
	}
}

test_aws_sts_get_caller_identity_green if {
	r := decide.result with input as mk("aws", "READ", {"iam_action": "sts:GetCallerIdentity"}, {}, 0)
	r.class == "green"
}

test_aws_iam_write_red_regardless_of_verb if {
	r := decide.result with input as mk("aws", "WRITE", {"iam_action": "iam:CreateAccessKey"}, {}, 0)
	r.class == "red"
	r.rule_id == "POL-401"
}

test_aws_iam_read_green if {
	r := decide.result with input as mk("aws", "READ", {"iam_action": "iam:GetRole"}, {}, 0)
	r.class == "green"
}

test_aws_delete_red if {
	r := decide.result with input as mk("aws", "DELETE", {"iam_action": "ec2:TerminateInstances", "resource": "i-123"}, {}, 0)
	r.class == "red"
	r.rule_id == "POL-402"
	r.decision == "hold"
}

test_aws_backup_delete_two_findings_one_rule_no_conflict if {
	r := decide.result with input as mk("aws", "DELETE", {"iam_action": "rds:DeleteDBSnapshot", "backup": true}, {}, 0)
	r.class == "red"
	r.rule_id == "POL-402"
	count([m | some m in r.matched; m.rule_id == "POL-402"]) == 2
}

test_aws_spend_over_threshold_held if {
	inp := object.union(mk("aws", "SPEND", {"iam_action": "ec2:RunInstances"}, {}, 0), {"action": object.union(mk("aws", "SPEND", {"iam_action": "ec2:RunInstances"}, {}, 0).action, {"est_cost_usd": 2400})})
	r := decide.result with input as inp
	r.class == "yellow"
	r.decision == "hold"
	r.rule_id == "POL-403"
}

test_aws_small_spend_green if {
	inp := object.union(mk("aws", "SPEND", {"iam_action": "ec2:RunInstances"}, {}, 0), {"action": object.union(mk("aws", "SPEND", {"iam_action": "ec2:RunInstances"}, {}, 0).action, {"est_cost_usd": 40})})
	r := decide.result with input as inp
	r.class == "green"
}

# --- Generic -------------------------------------------------------------

test_unknown_verb_denied_no_step_down if {
	r := decide.result with input as mk("gmail", "FROBNICATE", {}, {}, 0)
	r.class == "red"
	r.decision == "deny"
	r.rule_id == "POL-002"
	not r.ladder_change
}

test_unknown_system_denied if {
	r := decide.result with input as mk("salesforce_unknown", "READ", {}, {}, 0)
	r.decision == "deny"
	r.rule_id == "POL-002"
}
