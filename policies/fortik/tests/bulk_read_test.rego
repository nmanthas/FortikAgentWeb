package fortik.tests

import data.fortik.decide

bulk_read(rows, labels) := with_summary(pg("SELECT", "READ", "prod", {"tables": ["public.customers"]}), {"rows_estimate": rows, "data_labels": labels})

test_bulk_sensitive_read_held if {
	r := decide.result with input as bulk_read(12480, ["customer_pii"])
	r.class == "yellow"
	r.decision == "hold"
	r.rule_id == "POL-113"
	contains(r.reason, "12480")
}

test_small_sensitive_read_allowed if {
	r := decide.result with input as bulk_read(200, ["customer_pii"])
	r.decision == "allow"
}

test_bulk_read_without_sensitive_label_allowed if {
	r := decide.result with input as bulk_read(50000, ["internal"])
	r.decision == "allow"
}

# A sensitive read whose size could not be checked fails closed (POL-114).
test_sensitive_read_without_estimate_held if {
	r := decide.result with input as with_summary(pg("SELECT", "READ", "prod", {"tables": ["public.customers"]}), {"data_labels": ["customer_pii"]})
	r.class == "yellow"
	r.decision == "hold"
	r.rule_id == "POL-114"
}

test_read_without_estimate_or_sensitive_label_allowed if {
	r := decide.result with input as with_summary(pg("SELECT", "READ", "prod", {"tables": ["public.orders"]}), {"data_labels": ["internal"]})
	r.decision == "allow"
}

test_sensitive_read_with_small_estimate_not_pol114 if {
	r := decide.result with input as bulk_read(1, ["customer_pii"])
	r.decision == "allow"
}
