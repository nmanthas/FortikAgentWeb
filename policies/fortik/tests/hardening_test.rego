package fortik.tests

import data.fortik.decide

# Findings from the Phase 1 adversarial review: no unmatched risky action may
# default to green.

test_sensitive_data_external_via_http_red if {
	r := decide.result with input as mk("http", "SEND", {"external": true, "domain": "pastebin.com"}, {"data_labels": ["customer_pii"]}, 0)
	r.class == "red"
	r.rule_id == "POL-003"
	r.ladder_change.to == "ISOLATED"
}

test_sensitive_data_external_via_mcp_write_red if {
	r := decide.result with input as mk("mcp", "WRITE", {"external_domains": 1}, {"data_labels": ["financial"]}, 0)
	r.rule_id == "POL-003"
}

test_system_without_rules_side_effect_held if {
	every sys in ["mcp", "a2a", "http", "shell", "memory"] {
		r := decide.result with input as mk(sys, "EXECUTE", {}, {}, 0)
		r.class == "yellow"
		r.decision == "hold"
		r.rule_id == "POL-005"
	}
}

test_system_without_rules_read_allowed if {
	r := decide.result with input as mk("mcp", "READ", {"tool": "search_docs"}, {}, 0)
	r.decision == "allow"
}

test_gmail_drive_delete_held if {
	every sys in ["gmail", "drive"] {
		r := decide.result with input as mk(sys, "DELETE", {}, {}, 0)
		r.decision == "hold"
		r.rule_id == "POL-007"
	}
}

test_generic_spend_over_threshold_held if {
	base := mk("http", "SPEND", {"vendor": "stripe"}, {}, 0)
	inp := object.union(base, {"action": object.union(base.action, {"est_cost_usd": 2400})})
	r := decide.result with input as inp
	r.decision == "hold"
	"POL-008" in rule_ids(r)
}

test_malformed_boolean_fails_closed if {
	r := decide.result with input as mk("gmail", "SEND", {"external": "true"}, {"data_labels": ["customer_pii"], "recipients": 1}, 0)
	r.decision == "deny"
	r.rule_id == "POL-009"
	not r.ladder_change
}

test_malformed_external_domains_fails_closed if {
	r := decide.result with input as mk("gmail", "SEND", {"external_domains": "2"}, {"recipients": 1}, 0)
	r.decision == "deny"
	"POL-009" in rule_ids(r)
}

test_malformed_where_narrow_fails_closed if {
	r := decide.result with input as pg("DELETE", "DELETE", "prod", {"where_narrow": "yes", "undo_preparable": true})
	r.decision == "deny"
	"POL-009" in rule_ids(r)
}

test_merge_held_everywhere if {
	every env in ["prod", "staging"] {
		r := decide.result with input as pg("MERGE", "WRITE", env, {"merge_has_delete": true})
		r.decision == "hold"
		r.rule_id == "POL-111"
	}
}

test_upsert_on_prod_held if {
	r := decide.result with input as pg("INSERT", "WRITE", "prod", {"on_conflict_update": true})
	r.decision == "hold"
	r.rule_id == "POL-112"
}

test_plain_insert_on_prod_allowed if {
	r := decide.result with input as pg("INSERT", "WRITE", "prod", {"on_conflict_update": false})
	r.decision == "allow"
}

test_upsert_on_staging_allowed if {
	r := decide.result with input as pg("INSERT", "WRITE", "staging", {"on_conflict_update": true})
	r.decision == "allow"
}

test_copy_from_stdin_prod_held if {
	r := decide.result with input as pg("COPY_FROM_STDIN", "WRITE", "prod", {})
	r.rule_id == "POL-112"
}

test_push_and_merge_to_protected_record_ref if {
	every op in ["push", "merge_pr"] {
		r := decide.result with input as mk("github", "WRITE", {"repo": "acme/api", "branch": "main", "operation": op}, {}, 0)
		r.class == "yellow"
		r.decision == "allow_reduced"
		r.reduced_form.record_ref == true
	}
}

test_github_repo_delete_red if {
	r := decide.result with input as mk("github", "DELETE", {"repo": "acme/api", "operation": "delete_repo"}, {}, 0)
	r.class == "red"
	r.rule_id == "POL-304"
}

test_aws_delete_by_name_even_if_verb_write if {
	every act in ["s3:DeleteBucket", "ec2:TerminateInstances", "rds:DeleteDBSnapshot", "lambda:RemovePermission"] {
		r := decide.result with input as mk("aws", "WRITE", {"iam_action": act}, {}, 0)
		r.class == "red"
	}
}

test_aws_permission_changes_red if {
	every act in ["s3:PutBucketPolicy", "kms:PutKeyPolicy", "lambda:AddPermission", "ec2:AuthorizeSecurityGroupIngress", "s3:PutBucketAcl", "kms:CreateGrant", "ec2:ModifySnapshotAttribute"] {
		r := decide.result with input as mk("aws", "EXECUTE", {"iam_action": act}, {}, 0)
		r.class == "red"
		r.rule_id == "POL-404"
	}
}

test_aws_reads_still_green if {
	every act in ["s3:GetBucketPolicy", "lambda:ListPermissions", "s3:GetBucketAcl", "ec2:DescribeSnapshotAttribute"] {
		r := decide.result with input as mk("aws", "READ", {"iam_action": act}, {}, 0)
		r.class == "green"
	}
}

test_aws_spend_reason_prints_amount if {
	base := mk("aws", "SPEND", {"iam_action": "ec2:RunInstances"}, {}, 0)
	r := decide.result with input as object.union(base, {"action": object.union(base.action, {"est_cost_usd": 2400})})
	contains(r.reason, "$2400")
	contains(r.reason, "$500")
}

test_protected_branch_ref_spellings_red if {
	every b in ["refs/heads/main", "Main", "refs/heads/MASTER"] {
		r := decide.result with input as mk("github", "WRITE", {"branch": b, "operation": "force_push"}, {}, 0)
		r.rule_id == "POL-301"
	}
}

test_github_delete_by_operation_any_verb if {
	r := decide.result with input as mk("github", "WRITE", {"repo": "acme/api", "operation": "delete_repo"}, {}, 0)
	r.rule_id == "POL-304"
}

test_drive_enum_case_insensitive if {
	r := decide.result with input as mk("drive", "EXPORT", {"operation": "Share", "share_type": "Anyone"}, {}, 0)
	r.rule_id == "POL-211"
}

test_drive_external_non_share_export_held if {
	r := decide.result with input as mk("drive", "EXPORT", {"operation": "download_link", "external": true}, {}, 0)
	r.decision == "hold"
	r.rule_id == "POL-213"
}

test_prod_insert_missing_conflict_flag_held if {
	r := decide.result with input as pg("INSERT", "WRITE", "prod", {})
	r.rule_id == "POL-112"
}

test_spend_without_estimate_held if {
	every sys in ["aws", "http"] {
		r := decide.result with input as mk(sys, "SPEND", {"iam_action": "ec2:RunInstances"}, {}, 0)
		r.decision == "hold"
		"POL-008" in rule_ids(r)
	}
}

test_non_string_statement_type_denied if {
	r := decide.result with input as pg(42, "WRITE", "prod", {})
	r.decision == "deny"
	"POL-110" in rule_ids(r)
}

test_more_aws_destructive_and_sharing_actions if {
	every a in ["ecr:BatchDeleteImage", "kms:ScheduleKeyDeletion", "kms:DisableKey"] {
		r := decide.result with input as mk("aws", "WRITE", {"iam_action": a}, {}, 0)
		r.rule_id == "POL-402"
	}
	every a in ["ecr:SetRepositoryPolicy", "sqs:SetQueueAttributes", "glacier:SetVaultAccessPolicy"] {
		r := decide.result with input as mk("aws", "WRITE", {"iam_action": a}, {}, 0)
		r.rule_id == "POL-404"
	}
	every a in ["s3:PutBucketLifecycleConfiguration", "route53:ChangeResourceRecordSets"] {
		r := decide.result with input as mk("aws", "WRITE", {"iam_action": a}, {}, 0)
		r.decision == "hold"
	}
}

test_workflow_dispatch_held if {
	r := decide.result with input as mk("github", "EXECUTE", {"repo": "acme/api", "branch": "main", "operation": "run_workflow"}, {}, 0)
	r.decision == "hold"
	"POL-305" in rule_ids(r)
}

test_aws_code_execution_and_decrypt_held if {
	every a in ["ssm:SendCommand", "lambda:InvokeFunction", "lambda:UpdateFunctionCode", "kms:Decrypt"] {
		r := decide.result with input as mk("aws", "EXECUTE", {"iam_action": a, "resource": "*"}, {}, 0)
		r.decision == "hold"
		"POL-406" in rule_ids(r)
	}
}
