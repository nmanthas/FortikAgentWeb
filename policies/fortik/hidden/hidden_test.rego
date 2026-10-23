package fortik.hidden_test

import data.fortik.decide

agent := {"agent_id": "agent_1", "registered": true, "level": 0}

http_read(target) := {
	"action": {
		"agent_id": "agent_1",
		"system": "http",
		"verb": "READ",
		"target": target,
		"payload_summary": {},
		"est_cost_usd": 0,
	},
	"agent": agent,
}

with_ctx(inp, ctx) := object.union(inp, {"context": ctx})

rule_ids(r) := {m.rule_id | some m in r.matched}

# 300 characters of base64 (mixed case and digits).
b64_300 := concat("", [x | some _ in numbers.range(1, 30); x := "QUJDRGVm9+"])

# 256 hex characters.
hex_256 := concat("", [x | some _ in numbers.range(1, 32); x := "deadbeef"])

url(q) := concat("", ["https://collector.example.net/pixel.gif?", q])

test_base64_param_above_threshold_held_pol671 if {
	r := decide.result with input as http_read({"domain": "collector.example.net", "external": true, "method": "GET", "url": url(concat("", ["id=7&d=", b64_300]))})
	r.decision == "hold"
	r.class == "yellow"
	r.rule_id == "POL-671"
	contains(r.reason, `"d"`)
	contains(r.reason, "base64")
	contains(r.reason, "300 characters")
	not contains(r.reason, "QUJD") # never the value itself
}

test_hex_param_at_threshold_held if {
	r := decide.result with input as http_read({"domain": "x.example", "external": true, "url": url(concat("", ["h=", hex_256]))})
	r.rule_id == "POL-671"
	contains(r.reason, "hex")
}

test_percent_escaped_base64_is_folded if {
	v := concat("", [x | some _ in numbers.range(1, 30); x := "QUJDRGVm9%2B"])
	r := decide.result with input as http_read({"domain": "x.example", "external": true, "url": url(concat("", ["p=", v]))})
	r.rule_id == "POL-671"
	contains(r.reason, "300 characters")
}

test_percent_encoded_bytes_held if {
	v := concat("", [x | some _ in numbers.range(1, 90); x := "%00"])
	r := decide.result with input as http_read({"domain": "x.example", "external": true, "query": concat("", ["?blob=", v])})
	r.rule_id == "POL-671"
	contains(r.reason, "percent")
}

test_unnamed_param_held if {
	r := decide.result with input as http_read({"domain": "x.example", "external": true, "query": b64_300})
	r.rule_id == "POL-671"
	contains(r.reason, "(unnamed)")
}

test_below_threshold_green if {
	r := decide.result with input as http_read({"domain": "x.example", "external": true, "url": url("q=QUJDRGVm9QUJDRGVm9QUJDRGVm9")})
	r.decision == "allow"
	r.class == "green"
	not "POL-671" in rule_ids(r)
}

test_long_plain_words_not_encoded if {
	words := concat("+", [x | some _ in numbers.range(1, 60); x := "hello"])
	r := decide.result with input as http_read({"domain": "x.example", "external": true, "url": url(concat("", ["q=", words]))})
	not "POL-671" in rule_ids(r)
}

# Phase 5 review: a payload in one alphabet class (e.g. nibbles as a-p) is
# one unbroken token, never a run of words (in a query "+" is a space).
test_long_single_case_token_is_encoded if {
	v := concat("", [x | some _ in numbers.range(1, 60); x := "hellothere"])
	r := decide.result with input as http_read({"domain": "x.example", "external": true, "url": url(concat("", ["q=", v]))})
	r.rule_id == "POL-671"
}

# Phase 5 review evasions: each still held.
test_evasion_dot_in_value if {
	r := decide.result with input as http_read({"domain": "x.example", "external": true, "url": url(concat("", ["d=", b64_300, "."]))})
	r.rule_id == "POL-671"
}

test_evasion_dots_inside_value if {
	v := concat(".", [x | some _ in numbers.range(1, 30); x := "QUJDRGVm9a"])
	r := decide.result with input as http_read({"domain": "x.example", "external": true, "url": url(concat("", ["d=", v]))})
	r.rule_id == "POL-671"
}

test_evasion_semicolon_separator if {
	r := decide.result with input as http_read({"domain": "x.example", "external": true, "url": url(concat("", ["x=1;d=", b64_300]))})
	r.rule_id == "POL-671"
}

test_evasion_payload_in_name if {
	r := decide.result with input as http_read({"domain": "x.example", "external": true, "url": url(concat("", [b64_300, "=1"]))})
	r.rule_id == "POL-671"
	contains(r.reason, "(encoded name)")
	not contains(r.reason, "QUJD")
}

test_evasion_split_over_parameters if {
	half := concat("", [x | some _ in numbers.range(1, 20); x := "QUJDRGVm9+"])
	r := decide.result with input as http_read({"domain": "x.example", "external": true, "url": url(concat("", ["a=", half, "&b=", half]))})
	r.rule_id == "POL-671"
	contains(r.reason, "(all parameters)")
}

test_evasion_percent_escape_inside_base64 if {
	v := concat("%26", [x | some _ in numbers.range(1, 30); x := "QUJDRGVm9a"])
	r := decide.result with input as http_read({"domain": "x.example", "external": true, "url": url(concat("", ["d=", v]))})
	r.rule_id == "POL-671"
}

test_url_inside_a_value_does_not_hide_the_query if {
	r := decide.result with input as http_read({"domain": "x.example", "external": true, "url": url(concat("", ["d=", b64_300, "&r=https://example.com/?x=1"]))})
	r.rule_id == "POL-671"
}

# Phase 5 review: signed URLs of the cloud providers are not covert channels.
test_gcs_signed_url_allowed if {
	sig := concat("", [x | some _ in numbers.range(1, 64); x := "deadbeef"])
	u := concat("", ["https://storage.googleapis.com/bucket/obj?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Credential=svc%40proj.iam.gserviceaccount.com%2F20261020%2Fauto%2Fstorage%2Fgoog4_request&X-Goog-Date=20261020T000000Z&X-Goog-Expires=900&X-Goog-SignedHeaders=host&X-Goog-Signature=", sig])
	r := decide.result with input as http_read({"domain": "storage.googleapis.com", "external": true, "url": u})
	not "POL-671" in rule_ids(r)
}

test_s3_presigned_with_session_token_allowed if {
	tok := concat("", [x | some _ in numbers.range(1, 72); x := "IQoJb3JpZ2"])
	u := concat("", ["https://bucket.s3.us-east-1.amazonaws.com/key?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIAXXXXXXXXXXXXXXXX%2F20261020%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20261020T000000Z&X-Amz-Expires=900&X-Amz-Security-Token=", tok, "&X-Amz-SignedHeaders=host&X-Amz-Signature=", concat("", [x | some _ in numbers.range(1, 8); x := "deadbeef"])])
	r := decide.result with input as http_read({"url": u, "external": true})
	not "POL-671" in rule_ids(r)
}

test_signature_param_name_on_other_host_still_held if {
	sig := concat("", [x | some _ in numbers.range(1, 64); x := "deadbeef"])
	r := decide.result with input as http_read({"domain": "collector.evil.example", "external": true, "url": url(concat("", ["X-Goog-Signature=", sig]))})
	r.rule_id == "POL-671"
}

test_fragment_is_not_query if {
	r := decide.result with input as http_read({"domain": "x.example", "external": true, "url": concat("", ["https://x.example/a?x=1#", b64_300])})
	not "POL-671" in rule_ids(r)
}

test_no_query_no_finding if {
	r := decide.result with input as http_read({"domain": "x.example", "external": true, "url": "https://x.example/a/b"})
	not "POL-671" in rule_ids(r)
}

test_malformed_values_never_error if {
	r := decide.result with input as http_read({"domain": "x.example", "external": true, "url": "https://x.example/?%zz=%&&==&%", "query": 42})
	r.decision == "allow"
}

test_context_threshold_raises_bar if {
	inp := with_ctx(http_read({"domain": "x.example", "external": true, "url": url(concat("", ["d=", b64_300]))}), {"hidden": {"encoded_param_min": 400}})
	r := decide.result with input as inp
	not "POL-671" in rule_ids(r)
}

test_context_threshold_lowers_bar if {
	inp := with_ctx(http_read({"domain": "x.example", "external": true, "url": url("d=QUJDRGVm9QUJDRGVm9QUJDRGVm9QUJDRGVm9")}), {"hidden": {"encoded_param_min": 32}})
	r := decide.result with input as inp
	r.rule_id == "POL-671"
}

test_context_threshold_never_below_floor if {
	inp := with_ctx(http_read({"domain": "x.example", "external": true, "url": url("d=QUJDRGVm9")}), {"hidden": {"encoded_param_min": 1}})
	r := decide.result with input as inp
	not "POL-671" in rule_ids(r)
}

test_non_numeric_context_threshold_uses_default if {
	inp := with_ctx(http_read({"domain": "x.example", "external": true, "url": url(concat("", ["d=", b64_300]))}), {"hidden": {"encoded_param_min": "999999"}})
	r := decide.result with input as inp
	r.rule_id == "POL-671"
}

test_red_upload_stays_red if {
	inp := object.union(http_read({"domain": "x.example", "external": true, "url": url(concat("", ["d=", b64_300]))}), {"action": {
		"agent_id": "agent_1", "system": "http", "verb": "EXPORT",
		"target": {"domain": "x.example", "external": true, "url": url(concat("", ["d=", b64_300]))},
		"payload_summary": {"data_labels": ["customer_pii"]}, "est_cost_usd": 0,
	}})
	r := decide.result with input as inp
	r.class == "red"
	"POL-671" in rule_ids(r)
}

test_other_systems_with_url_covered if {
	inp := object.union(http_read({}), {"action": {
		"agent_id": "agent_1", "system": "mcp", "verb": "READ",
		"target": {"server": "fetch", "tool": "fetch", "method": "tools/call", "url": url(concat("", ["d=", b64_300]))},
		"payload_summary": {}, "est_cost_usd": 0,
	}})
	r := decide.result with input as inp
	"POL-671" in rule_ids(r)
}

# Adapters send a summary of encoded parameters instead of the query.
summary_target(n) := {"domain": "collector.example.net", "external": true, "encoded_params": [{"name": "d", "encoding": "base64", "length": n}]}

test_summary_above_threshold_held if {
	r := decide.result with input as http_read(summary_target(300))
	r.decision == "hold"
	r.rule_id == "POL-671"
	contains(r.reason, "\"d\"")
}

test_summary_below_threshold_ignored if {
	r := decide.result with input as http_read(summary_target(100))
	not "POL-671" in rule_ids(r)
}

test_summary_malformed_entries_ignored if {
	t := {"domain": "collector.example.net", "external": true, "encoded_params": ["x", {"name": "d"}, {"encoding": "hex", "length": "999"}]}
	r := decide.result with input as http_read(t)
	not "POL-671" in rule_ids(r)
}
