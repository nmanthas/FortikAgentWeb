# AWS rules. Adapter contract (Phase 2 app gateway / broker):
#   target.iam_action (e.g. "ec2:TerminateInstances"), target.resource,
#   target.backup (bool, resource is a backup/snapshot), est_cost_usd.
package fortik.rules

aws if act.system == "aws"

aws_action := lower(object.get(tgt, "iam_action", ""))

aws_read_prefixes := ["get", "list", "describe", "head", "lookup", "batchget", "scan", "query", "select"]

aws_read_only if {
	parts := split(aws_action, ":")
	count(parts) == 2
	some p in aws_read_prefixes
	startswith(parts[1], p)
}

# POL-401: any non-read IAM/Organizations/STS-federation change is red
# (independent of how the adapter mapped the verb).
findings contains {
	"rule_id": "POL-401",
	"class": "red",
	"reason": sprintf("AWS identity change %s", [aws_action]),
	"ladder": "ISOLATED",
} if {
	aws
	some prefix in ["iam:", "organizations:", "sso:", "identitystore:"]
	startswith(aws_action, prefix)
	not aws_read_only
}

# POL-401: STS calls that mint or reshape credentials (AssumeRole*,
# GetFederationToken, GetSessionToken, TagSession, SetSourceIdentity, ...)
# are red: a chained credential is not narrowed by Fortik's session policy.
# Only the pure identity lookups stay green. (GetFederationToken and
# GetSessionToken start with "get", so this does not rely on aws_read_only.)
aws_sts_lookups := {"sts:getcalleridentity", "sts:getaccesskeyinfo", "sts:decodeauthorizationmessage"}

findings contains {
	"rule_id": "POL-401",
	"class": "red",
	"reason": sprintf("AWS credential-minting STS call %s escapes the session policy", [aws_action]),
	"ladder": "ISOLATED",
} if {
	aws
	startswith(aws_action, "sts:")
	not aws_action in aws_sts_lookups
}

# POL-402: AWS resource deletion is not undoable in the MVP: hold as red.
findings contains {
	"rule_id": "POL-402",
	"class": "red",
	"reason": sprintf("AWS deletion %s on %v is not undoable", [aws_action, object.get(tgt, "resource", "")]),
	"ladder": "ISOLATED",
} if {
	aws
	act.verb == "DELETE"
}

findings contains {
	"rule_id": "POL-402",
	"class": "red",
	"reason": sprintf("AWS backup deletion/modification %s", [aws_action]),
	"ladder": "ISOLATED",
} if {
	aws
	tgt.backup == true
	not aws_read_only
}

# POL-403: spend above the threshold needs approval.
findings contains {
	"rule_id": "POL-403",
	"class": "yellow",
	"reason": sprintf("AWS spend estimate $%v exceeds $%v: approval required", [act.est_cost_usd, cfg.aws_spend_approval_usd]),
	"hold": true,
} if {
	aws
	object.get(act, "est_cost_usd", 0) > cfg.aws_spend_approval_usd
}

aws_op := lower(substring(aws_action, indexof(aws_action, ":") + 1, -1)) if contains(aws_action, ":")

# POL-402 by action name: deletions are red even if the adapter mapped the
# verb to WRITE or EXECUTE.
findings contains {
	"rule_id": "POL-402",
	"class": "red",
	"reason": sprintf("AWS deletion %s on %v is not undoable", [aws_action, object.get(tgt, "resource", "")]),
	"ladder": "ISOLATED",
} if {
	aws
	not aws_read_only
	some p in ["delete", "terminate", "remove", "purge", "destroy", "deregister", "disable", "deletion"]
	contains(aws_op, p)
}

# POL-404: permission and sharing changes outside IAM (resource policies,
# ACLs, security-group ingress, KMS grants, snapshot/AMI sharing).
aws_permission_change if {
	startswith(aws_op, "put")
	contains(aws_op, "policy")
}

aws_permission_change if {
	startswith(aws_op, "attach")
	contains(aws_op, "policy")
}

aws_permission_change if contains(aws_op, "permission")

aws_permission_change if startswith(aws_op, "authorize")

aws_permission_change if {
	startswith(aws_op, "set")
	some w in ["policy", "acl", "attributes"]
	contains(aws_op, w)
}

aws_permission_change if {
	contains(aws_op, "acl")
	not aws_read_only
}

aws_permission_change if aws_op in {"creategrant", "modifysnapshotattribute", "modifyimageattribute", "modifydbsnapshotattribute", "modifydbclustersnapshotattribute"}

findings contains {
	"rule_id": "POL-404",
	"class": "red",
	"reason": sprintf("AWS permission/sharing change %s", [aws_action]),
	"ladder": "ISOLATED",
} if {
	aws
	not aws_read_only
	aws_permission_change
}

# POL-405: changes that can destroy data later or redirect traffic (lifecycle
# expiry rules, DNS record changes) need approval.
findings contains {
	"rule_id": "POL-405",
	"class": "yellow",
	"reason": sprintf("AWS %s can delete data later or redirect traffic: approval required", [aws_action]),
	"hold": true,
} if {
	aws
	not aws_read_only
	some w in ["lifecycle", "changeresourcerecordsets"]
	contains(aws_op, w)
}

# POL-406: remote code execution, function code changes and decryption are
# powerful even on a single resource: approval required.
findings contains {
	"rule_id": "POL-406",
	"class": "yellow",
	"reason": sprintf("AWS %s executes code or decrypts data: approval required", [aws_action]),
	"hold": true,
} if {
	aws
	aws_action in {"ssm:sendcommand", "ssm:startsession", "lambda:invokefunction", "lambda:updatefunctioncode", "lambda:updatefunctionconfiguration", "kms:decrypt", "ecs:runtask", "ecs:executecommand"}
}
