# Hidden-signal rules that the policy can see on one action
# (docs/PHASE5_DESIGN.md §2, rule range POL-670..679). The communication map
# (internal/commap) applies the same deterministic detection when it rolls
# actions up into edges: it marks the edge "hidden" and raises a
# hidden_signal alert. Keep the two in step (commap.FindEncodedParams).
#
# POL-671: a URL query carries an encoded payload (base64 or base64url, hex,
# or percent-encoded bytes) of at least encoded_param_min characters, in one
# parameter (its name or value) or split over several: a covert exfiltration
# channel through an innocuous-looking request. Yellow, held for a human.
# Parameters are split on "&" and ";"; a part is measured by its runs of
# encoding-alphabet characters (so an inserted "." or "%26" does not hide a
# payload); the signature parameters of signed URLs on the provider's own
# hosts (GCS, S3, Azure Blob) are not measured.
#
# Inputs: target.url (a full URL: the query is the text after the first "?"
# up to "#"), target.query (a raw query string) and target.encoded_params (an
# adapter's summary). Only builtins that cannot fail on arbitrary input are
# used (no URL decoding): a malformed URL must never turn the evaluation into
# an error.
#
# Threshold: input.context.hidden.encoded_param_min (the commap enricher
# supplies map.encoded_param_min), else data.fortik.hidden.encoded_param_min.
# It is never lower than data.fortik.hidden.encoded_param_floor.
package fortik.rules

hidden_cfg := data.fortik.hidden

hidden_min := max({hidden_cfg.encoded_param_floor, m}) if {
	m := input.context.hidden.encoded_param_min
	is_number(m)
} else := hidden_cfg.encoded_param_min

hidden_queries contains q if {
	u := tgt.url
	is_string(u)
	nofrag := split(u, "#")[0]
	i := indexof(nofrag, "?")
	i >= 0
	q := substring(nofrag, i + 1, -1)
}

hidden_queries contains q if {
	raw := tgt.query
	is_string(raw)
	q := trim_prefix(raw, "?")
}

# [name, raw value] of every query parameter (split on "&" and ";"); a part
# without "=" is a value with an empty name.
hidden_kv(part) := [substring(part, 0, i), substring(part, i + 1, -1)] if {
	i := indexof(part, "=")
	i >= 0
} else := ["", part]

hidden_parts contains [q, i, part] if {
	some q in hidden_queries
	some i, part in regex.split(`[&;]`, q)
	part != ""
}

# The common percent-escapes of base64 ("+", "/", "=") are folded back so an
# escaped base64 value is measured and matched like a plain one; any other
# %XX escape is dropped (it cannot split a payload into short runs).
hidden_norm(raw) := strings.replace_n({"%2B": "+", "%2b": "+", "%2F": "/", "%2f": "/", "%3D": "=", "%3d": "="}, raw)

hidden_strip(raw) := regex.replace(hidden_norm(raw), `%[0-9A-Fa-f]{2}`, "")

hidden_classes(v) := count({c | some c in ["[A-Z]", "[a-z]", "[0-9]"]; regex.match(c, v)})

# A run of encoding-alphabet characters looks encoded when it mixes two of
# upper/lower/digits (8+), or is one unbroken single-class token of 32+ (in a
# query "+" is a space: "hello+world" is words).
hidden_run_ok(r) if hidden_classes(r) >= 2

hidden_run_ok(r) if {
	not contains(r, "+")
	count(r) >= 32
}

hidden_runs(raw) := [r | some r in regex.find_n(`[A-Za-z0-9+/_-]{8,}`, hidden_strip(raw), -1); hidden_run_ok(r)]

# Parameter names are measured only by long runs (32+): names such as
# "X-Goog-Algorithm" or "utm_campaign" are short; a payload in a name is not.
hidden_name_len(raw) := sum([count(r) | some r in hidden_runs(raw); count(r) >= 32])

hidden_pct(raw) := max(array.concat([0], [count(r) | some r in regex.find_n(`(%[0-9A-Fa-f]{2})+`, raw, -1)]))

hidden_b64(raw) := sum([count(r) | some r in hidden_runs(raw)])

hidden_all_hex(raw) if every r in hidden_runs(raw) {
	regex.match(`^[0-9A-Fa-f]+$`, r)
}

# [encoding, length] of a name or value; ["", 0] when nothing looks encoded.
hidden_measure(raw) := ["percent", hidden_pct(raw)] if {
	hidden_pct(raw) > 0
	hidden_pct(raw) >= hidden_b64(raw)
} else := ["hex", hidden_b64(raw)] if {
	hidden_b64(raw) > 0
	hidden_all_hex(raw)
} else := ["base64", hidden_b64(raw)] if {
	hidden_b64(raw) > 0
} else := ["", 0]

# One entry per parameter with encoded content: its name (or "(encoded
# name)" when the name itself carries the payload; never echoed) and the
# combined size of name and value.
hidden_entries contains {"k": [crypto.md5(x[0]), x[1]], "name": n, "encoding": enc, "length": nl + vm[1]} if {
	some x in hidden_parts
	kv := hidden_kv(x[2])
	nl := hidden_name_len(kv[0])
	vm := hidden_measure(kv[1])
	nl + vm[1] > 0
	enc := hidden_pick(nl, kv[0], vm)
	n := hidden_shown(kv[0], nl)
}

hidden_pick(nl, name, vm) := hidden_name_enc(name) if nl > vm[1]

else := vm[0]

hidden_name_enc(name) := "hex" if {
	every r in [r | some r in hidden_runs(name); count(r) >= 32] {
		regex.match(`^[0-9A-Fa-f]+$`, r)
	}
} else := "base64"

hidden_shown(name, nl) := "(encoded name)" if {
	nl > 0
} else := hidden_clip(name)

# Adapters that do not store the query send a summary instead:
# target.encoded_params = [{name, encoding, length}] (no values).
hidden_entries contains {"k": ["summary", i], "name": hidden_clip(object.get(p, "name", "")), "encoding": p.encoding, "length": p.length} if {
	ps := object.get(tgt, "encoded_params", [])
	is_array(ps)
	some i, p in ps
	is_object(p)
	is_string(p.encoding)
	p.encoding != ""
	is_number(p.length)
	p.length > 0
}

hidden_clip(n) := substring(n, 0, 64) if is_string(n)

else := ""

# Signed URLs: the providers' signature and credential parameters on their
# own hosts are not measured (data.fortik.hidden.signed_url_params).
hidden_host := lower(trim_suffix(tgt.domain, ".")) if {
	is_string(tgt.domain)
	tgt.domain != ""
} else := lower(trim_suffix(m[0][2], ".")) if {
	is_string(tgt.url)
	m := regex.find_all_string_submatch_n(`^[A-Za-z][A-Za-z0-9+.-]*://([^/?#@]*@)?([^/?#:]+)`, tgt.url, 1)
	count(m) > 0
} else := ""

hidden_signed(name) if {
	some suffix, names in object.get(hidden_cfg, "signed_url_params", {})
	hidden_host_under(suffix)
	lower(name) in names
}

hidden_host_under(suffix) if hidden_host == suffix

hidden_host_under(suffix) if endswith(hidden_host, concat("", [".", suffix]))

hidden_counted contains e if {
	some e in hidden_entries
	not hidden_signed(e.name)
}

hidden_split := [e | some e in hidden_counted; e.length >= hidden_cfg.encoded_param_floor]

hidden_total := sum([e.length | some e in hidden_split])

hidden_encoded contains {"name": e.name, "encoding": e.encoding, "length": e.length} if {
	some e in hidden_counted
	e.length >= hidden_min
}

# A payload split over parameters each below the threshold is still seen.
hidden_encoded contains {"name": "(all parameters)", "encoding": "split", "length": hidden_total} if {
	count(hidden_split) >= 2
	hidden_total >= hidden_min
}

# The longest encoded parameter names the finding (deterministic order).
hidden_top := sort([[0 - e.length, e.name, e.encoding] | some e in hidden_encoded])[0]

hidden_name(n) := "(unnamed)" if n == ""

else := substring(n, 0, 64)

findings contains {
	"rule_id": "POL-671",
	"class": "yellow",
	"reason": sprintf(
		"URL parameter %q carries a %s-encoded value of %d characters (threshold %d) in %d parameter(s): possible covert channel, approval required",
		[hidden_name(hidden_top[1]), hidden_top[2], 0 - hidden_top[0], hidden_min, count(hidden_encoded)],
	),
	"hold": true,
} if {
	count(hidden_encoded) > 0
}
