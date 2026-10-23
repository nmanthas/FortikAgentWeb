package commap

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// RuleEncodedParam is the policy finding for an encoded URL parameter
// (policies/fortik/hidden). FindEncodedParams is its Go twin: the map marks
// the edge hidden whether or not the policy bundle in force had the rule.
const RuleEncodedParam = "POL-671"

// EncodedParamFloor mirrors data.fortik.hidden.encoded_param_floor: no
// threshold is ever lower.
const EncodedParamFloor = 16

// EncodedParam describes one query parameter that looks like an encoded
// payload. It carries the parameter name and sizes only, never the value.
type EncodedParam struct {
	Name     string `json:"name"`
	Encoding string `json:"encoding"` // base64 | hex | percent | split (the request's total)
	Length   int    `json:"length"`
}

// Names used in findings instead of attacker-chosen text.
const (
	NameEncoded = "(encoded name)"    // the parameter name itself carries the payload
	NameAll     = "(all parameters)"  // the encoded content of the whole query
	NameMore    = "(more parameters)" // a summary's remainder beyond MaxSummaryParams
)

// Mirrors hidden.rego: a run of encoding-alphabet characters counts from 8
// characters when it mixes two of upper/lower/digits, and from 32 when it is
// one unbroken single-class token (words are shorter, and in a query "+" is
// a space); a parameter counts toward the request's total from 16.
const (
	tokenMin = 32
	splitMin = EncodedParamFloor
)

var (
	pctRunRe    = regexp.MustCompile(`(%[0-9A-Fa-f]{2})+`)
	escapeRe    = regexp.MustCompile(`%[0-9A-Fa-f]{2}`)
	runRe       = regexp.MustCompile(`[A-Za-z0-9+/_-]{8,}`)
	hexRe       = regexp.MustCompile(`^[0-9A-Fa-f]+$`)
	upperRe     = regexp.MustCompile(`[A-Z]`)
	lowerRe     = regexp.MustCompile(`[a-z]`)
	digitRe     = regexp.MustCompile(`[0-9]`)
	sepRe       = regexp.MustCompile(`[&;]`)
	hostRe      = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://([^/?#@]*@)?([^/?#:]+)`)
	b64Replacer = strings.NewReplacer("%2B", "+", "%2b", "+", "%2F", "/", "%2f", "/", "%3D", "=", "%3d", "=")
)

// SignedURLParams are the signature and credential parameters of the cloud
// providers' signed URLs, exempt on the provider's own hosts (a host equal
// to the key or ending in "."+key). Mirrors data.fortik.hidden.signed_url_params.
var SignedURLParams = map[string][]string{
	"storage.googleapis.com": {"x-goog-signature", "x-goog-credential", "x-goog-security-token", "googleaccessid", "signature"},
	"amazonaws.com":          {"x-amz-signature", "x-amz-security-token", "x-amz-credential", "signature", "awsaccesskeyid"},
	"blob.core.windows.net":  {"sig"},
}

// FindEncodedParams returns what in target.url / target.query (and an
// adapter's target.encoded_params summary) looks like an encoded payload of
// at least min characters, longest first. The detection is POL-671's
// (deterministic, no decoding):
//
//   - parameters are split on "&" and ";", and both the name and the value
//     are measured;
//   - a part's size is the total length of its runs of base64/hex alphabet
//     characters ([A-Za-z0-9+/_-], after folding %2B %2F %3D and dropping
//     other %XX escapes) that look encoded (at least 8 long mixing two of
//     upper, lower and digits, or one unbroken single-class token without
//     "+", which in a query is a space, of at least 32), or its longest run
//     of %XX escapes, whichever is larger;
//   - one parameter at or above min is a finding, and so is the request's
//     total (encoding "split") of the parameters with at least 16 encoded
//     characters when there are two or more, so a payload split over
//     parameters below min is still seen;
//   - the signature parameters of signed URLs on the provider's own hosts
//     (SignedURLParams) are not measured.
func FindEncodedParams(target map[string]any, min int) []EncodedParam {
	if min < EncodedParamFloor {
		min = EncodedParamFloor
	}
	var queries []string
	if u, ok := target["url"].(string); ok {
		if q, ok := urlQuery(u); ok {
			queries = append(queries, q)
		}
	}
	if q, ok := target["query"].(string); ok {
		queries = append(queries, strings.TrimPrefix(q, "?"))
	}
	entries := summaryParams(target["encoded_params"])
	for _, q := range queries {
		entries = append(entries, measureQuery(q)...)
	}
	host := targetHost(target)
	var counted []EncodedParam
	total := 0
	var out []EncodedParam
	seen := map[EncodedParam]bool{}
	for _, e := range entries {
		if e.Length <= 0 || signedParam(host, e.Name) {
			continue
		}
		if e.Length >= splitMin {
			counted = append(counted, e)
			total += e.Length
		}
		if e.Length >= min && !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	if len(counted) >= 2 && total >= min {
		out = append(out, EncodedParam{Name: NameAll, Encoding: "split", Length: total})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Length != out[j].Length {
			return out[i].Length > out[j].Length
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Encoding < out[j].Encoding
	})
	return out
}

// urlQuery is the text after the first "?" of a URL, up to "#".
func urlQuery(u string) (string, bool) {
	u, _, _ = strings.Cut(u, "#")
	_, q, ok := strings.Cut(u, "?")
	return q, ok
}

// targetHost is target.domain, else the host of target.url (lower case).
func targetHost(t map[string]any) string {
	if d, ok := t["domain"].(string); ok && d != "" {
		return strings.TrimSuffix(strings.ToLower(d), ".")
	}
	if u, ok := t["url"].(string); ok {
		if m := hostRe.FindStringSubmatch(u); m != nil {
			return strings.TrimSuffix(strings.ToLower(m[2]), ".")
		}
	}
	return ""
}

func signedParam(host, name string) bool {
	if host == "" {
		return false
	}
	n := strings.ToLower(name)
	for suffix, names := range SignedURLParams {
		if host != suffix && !strings.HasSuffix(host, "."+suffix) {
			continue
		}
		for _, x := range names {
			if n == x {
				return true
			}
		}
	}
	return false
}

// measureQuery measures every parameter of a raw query (entries with a
// positive length only).
func measureQuery(q string) []EncodedParam {
	var out []EncodedParam
	for _, part := range sepRe.Split(q, -1) {
		if part == "" {
			continue
		}
		name, val := "", part
		if i := strings.IndexByte(part, '='); i >= 0 {
			name, val = part[:i], part[i+1:]
		}
		ne, nl := measureName(name)
		ve, vl := measure(val)
		if nl+vl == 0 {
			continue
		}
		enc := ve
		if nl > vl {
			enc = ne
		}
		shown := clipName(name)
		if nl > 0 {
			shown = NameEncoded // never echo an encoded name (it is the payload)
		}
		out = append(out, EncodedParam{Name: shown, Encoding: enc, Length: nl + vl})
	}
	return out
}

// measure is one name's or value's encoded size and its encoding.
func measure(raw string) (string, int) {
	pct := 0
	for _, r := range pctRunRe.FindAllString(raw, -1) {
		pct = max(pct, utf8.RuneCountInString(r))
	}
	stripped := escapeRe.ReplaceAllString(b64Replacer.Replace(raw), "")
	b64, allHex := 0, true
	for _, r := range runRe.FindAllString(stripped, -1) {
		if !runLooksEncoded(r) {
			continue
		}
		b64 += utf8.RuneCountInString(r)
		if !hexRe.MatchString(r) {
			allHex = false
		}
	}
	switch {
	case pct > 0 && pct >= b64:
		return "percent", pct
	case b64 > 0 && allHex:
		return "hex", b64
	case b64 > 0:
		return "base64", b64
	}
	return "", 0
}

// measureName measures a parameter name by its long runs only (32+): names
// such as "X-Goog-Algorithm" or "utm_campaign" are short; a payload is not.
func measureName(raw string) (string, int) {
	n, allHex := 0, true
	for _, r := range runRe.FindAllString(escapeRe.ReplaceAllString(b64Replacer.Replace(raw), ""), -1) {
		if !runLooksEncoded(r) || utf8.RuneCountInString(r) < tokenMin {
			continue
		}
		n += utf8.RuneCountInString(r)
		if !hexRe.MatchString(r) {
			allHex = false
		}
	}
	switch {
	case n > 0 && allHex:
		return "hex", n
	case n > 0:
		return "base64", n
	}
	return "", 0
}

// runLooksEncoded: two of upper/lower/digit, or one unbroken token (no "+":
// in a query "+" is a space, so "hello+world" is words, not a payload).
func runLooksEncoded(r string) bool {
	classes := 0
	for _, re := range []*regexp.Regexp{upperRe, lowerRe, digitRe} {
		if re.MatchString(r) {
			classes++
		}
	}
	return classes >= 2 || (!strings.Contains(r, "+") && utf8.RuneCountInString(r) >= tokenMin)
}

// clipName bounds a parameter name for alerts (names are attacker-chosen).
func clipName(n string) string {
	if len(n) > 64 {
		n = n[:64]
		for !utf8.ValidString(n) {
			n = n[:len(n)-1]
		}
	}
	return n
}

// MaxSummaryParams bounds target.encoded_params (the rest is summed into
// one NameMore entry, so the request's total stays exact).
const MaxSummaryParams = 32

// SummarizeRawQuery returns target.encoded_params for an adapter from a raw
// query string (the part after "?"): every parameter with encoded content,
// as plain JSON values with name, encoding and length only, never the value.
// Nil when there are none.
func SummarizeRawQuery(q string) []any {
	return summarize(measureQuery(strings.TrimPrefix(q, "?")))
}

// SummarizeURL is SummarizeRawQuery for a full URL (its query is the text
// after the first "?", up to "#"; "://" or "?" inside a value do not matter).
func SummarizeURL(u string) []any {
	q, ok := urlQuery(u)
	if !ok {
		return nil
	}
	return SummarizeRawQuery(q)
}

func summarize(ps []EncodedParam) []any {
	sort.SliceStable(ps, func(i, j int) bool { return ps[i].Length > ps[j].Length })
	var out []any
	rest := 0
	for i, p := range ps {
		if i >= MaxSummaryParams-1 && len(ps) > MaxSummaryParams {
			rest += p.Length
			continue
		}
		out = append(out, map[string]any{"name": p.Name, "encoding": p.Encoding, "length": p.Length})
	}
	if rest > 0 {
		out = append(out, map[string]any{"name": NameMore, "encoding": "split", "length": rest})
	}
	return out
}

// summaryParams reads target.encoded_params ([]any of objects after JSON,
// or []EncodedParam in process); malformed entries are skipped.
func summaryParams(v any) []EncodedParam {
	var out []EncodedParam
	switch xs := v.(type) {
	case []EncodedParam:
		return append(out, xs...)
	case []any:
		for _, x := range xs {
			m, ok := x.(map[string]any)
			if !ok {
				continue
			}
			name, _ := m["name"].(string)
			enc, _ := m["encoding"].(string)
			var n int
			switch l := m["length"].(type) {
			case int:
				n = l
			case float64:
				n = int(l)
			case json.Number:
				i, _ := l.Int64()
				n = int(i)
			}
			if enc == "" || n <= 0 {
				continue
			}
			out = append(out, EncodedParam{Name: clipName(name), Encoding: enc, Length: n})
		}
	}
	return out
}
