# Google Workspace rules (Gmail, Drive). The app gateway (Phase 2) produces
# these Actions; OAuth scopes are coarse, so recipient/share/volume rules are
# enforced here.
#
# Adapter contract:
#   gmail SEND: target.to/cc/bcc, target.external_domains (count),
#               payload_summary.recipients (total), data_labels
#   drive share / link: verb EXPORT, target.operation = "share",
#               target.share_type = "user"|"group"|"domain"|"anyone",
#               target.external (bool, grantee outside the company)
package fortik.rules

recipients := object.get(summary, "recipients", 0)

# POL-201: customer/sensitive data to an external recipient is red.
findings contains {
	"rule_id": "POL-201",
	"class": "red",
	"reason": sprintf("email with sensitive data %v to external recipients", [sort([l | some l in sensitive])]),
	"ladder": "ISOLATED",
} if {
	act.system == "gmail"
	act.verb == "SEND"
	external
	count(sensitive) > 0
}

# POL-202: any external send goes out only after a delay held in the gateway
# (the undo window: cancel before it elapses).
findings contains {
	"rule_id": "POL-202",
	"class": "yellow",
	"reason": sprintf("external email: delayed %ds so it can be cancelled", [cfg.gmail_send_delay_seconds]),
	"reduced_form": {"delay_send_seconds": cfg.gmail_send_delay_seconds},
} if {
	act.system == "gmail"
	act.verb == "SEND"
	external
}

# POL-203: bulk sends need approval.
findings contains {
	"rule_id": "POL-203",
	"class": "yellow",
	"reason": sprintf("bulk email to %d recipients (limit %d): approval required", [recipients, cfg.gmail_bulk_recipients]),
	"hold": true,
} if {
	act.system == "gmail"
	act.verb == "SEND"
	recipients > cfg.gmail_bulk_recipients
}

share_type := lower(object.get(tgt, "share_type", ""))

drive_share if {
	act.system == "drive"
	act.verb == "EXPORT"
	lower(object.get(tgt, "operation", "")) == "share"
}

# POL-213: any other Drive export leaving the company (download link, copy to
# an external drive...) has no narrowing or undo in the MVP: approval.
findings contains {
	"rule_id": "POL-213",
	"class": "yellow",
	"reason": "Drive export to an external destination: approval required",
	"hold": true,
} if {
	act.system == "drive"
	act.verb == "EXPORT"
	not drive_share
	external
}

# POL-211: public links and external shares are narrowed to the company
# domain; the permission id is recorded so the share can be undone.
findings contains {
	"rule_id": "POL-211",
	"class": "yellow",
	"reason": "Drive public/external share narrowed to internal domain",
	"reduced_form": {"narrow_share": "domain", "record_permission": true},
} if {
	drive_share
	share_type == "anyone"
}

findings contains {
	"rule_id": "POL-211",
	"class": "yellow",
	"reason": "Drive public/external share narrowed to internal domain",
	"reduced_form": {"narrow_share": "domain", "record_permission": true},
} if {
	drive_share
	external
	count(sensitive) == 0
}

# POL-212: sharing a sensitive file directly with an external person is red.
findings contains {
	"rule_id": "POL-212",
	"class": "red",
	"reason": sprintf("Drive share of sensitive data %v with an external grantee", [sort([l | some l in sensitive])]),
	"ladder": "ISOLATED",
} if {
	drive_share
	external
	share_type != "anyone"
	count(sensitive) > 0
}
