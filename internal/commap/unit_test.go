package commap_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"fortik/internal/action"
	"fortik/internal/commap"
	"fortik/internal/control"
	"fortik/internal/policy"
)

// The Go detector and POL-671 must agree on every case (the map marks the
// edge hidden even if the bundle in force lacked the rule; they must not drift).
func TestEncodedParamsMatchPolicy(t *testing.T) {
	eng, err := policy.NewEngine(context.Background(), policyDir(), discard())
	if err != nil {
		t.Fatal(err)
	}
	b64 := strings.Repeat("QUJDRGVm9+", 30)
	cases := []map[string]any{
		{"url": "https://x.example/a?d=" + b64},
		{"url": "https://x.example/a?d=" + strings.Repeat("QUJDRGVm9%2B", 30)},
		{"url": "https://x.example/a?h=" + strings.Repeat("deadbeef", 32)},
		{"url": "https://x.example/a?h=" + strings.Repeat("deadbeef", 31)},
		{"query": "blob=" + strings.Repeat("%00", 90)},
		{"query": "?" + b64},
		{"url": "https://x.example/a?q=" + strings.Repeat("hello+", 60)},
		{"url": "https://x.example/a?q=" + strings.Repeat("hellothere", 60)},
		{"url": "https://x.example/a?x=1#" + b64},
		{"url": "https://x.example/a/" + b64},
		{"url": "https://x.example/?%zz=%&&==&%"},
		{"url": "https://x.example/a?a=1&b=" + strings.Repeat("A1", 128)},
		{"url": "https://x.example/a?a=1&b=" + strings.Repeat("A1", 127) + "="},
		{"query": 42},
		// Phase 5 review: evasions and signed URLs (Go and Rego must agree).
		{"url": "https://x.example/a?d=" + b64 + "."},
		{"url": "https://x.example/a?d=" + strings.Repeat("QUJDRGVm9a.", 30)},
		{"url": "https://x.example/a?x=1;d=" + b64},
		{"url": "https://x.example/a?" + b64 + "=1"},
		{"url": "https://x.example/a?a=" + b64[:200] + "&b=" + b64[:200]},
		{"url": "https://x.example/a?d=" + strings.Repeat("QUJDRGVm9a%26", 30)},
		{"url": "https://x.example/a?d=" + b64 + "&r=https://example.com/?x=1"},
		{"url": "https://x.example/a?q=" + strings.Repeat("hellothere", 60)},
		{"url": "https://x.example/a?utm_source=newsletter&utm_campaign=spring2026sale&session=abcd1234efgh5678"},
		{"domain": "storage.googleapis.com", "url": "https://storage.googleapis.com/b/o?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Date=20261020T000000Z&X-Goog-Signature=" + strings.Repeat("deadbeef", 64)},
		{"url": "https://b.s3.us-east-1.amazonaws.com/k?X-Amz-Security-Token=" + strings.Repeat("IQoJb3JpZ2", 72) + "&X-Amz-Signature=" + strings.Repeat("deadbeef", 8)},
		{"domain": "evil.example", "url": "https://evil.example/a?X-Goog-Signature=" + strings.Repeat("deadbeef", 64)},
	}
	for i, tgt := range cases {
		in := policy.Input{Action: action.Action{AgentID: "a", System: "http", Verb: action.VerbRead, Target: tgt},
			Agent: control.State{AgentID: "a", Registered: true}}
		res, err := eng.Eval(context.Background(), in)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		fired := false
		for _, m := range res.Matched {
			if m.RuleID == commap.RuleEncodedParam {
				fired = true
			}
		}
		got := len(commap.FindEncodedParams(tgt, 256)) > 0
		if fired != got {
			t.Errorf("case %d: policy fired=%v, Go detector=%v", i, fired, got)
		}
	}
}

func TestValidNode(t *testing.T) {
	good := []string{"agent:fin_1", "instance:i-1", "user:cfo@acme.test", "app:gmail", "store:postgres:finance",
		"memory:support/kb", "mcp:github-mcp", "domain:evil.example", "domain:10.0.0.1", "domain:unknown", "domain:anyone"}
	bad := []string{"", "agent:", "agent:bad id", "user:not-an-email", "app:Gmail", "store:mysql:x", "memory:support",
		"mcp:", "domain:-bad-.example", "galaxy:x", "domain:evil.example/path", "agent:" + strings.Repeat("a", 200)}
	for _, n := range good {
		if !commap.ValidNode(n) {
			t.Errorf("%q should be valid", n)
		}
	}
	for _, n := range bad {
		if commap.ValidNode(n) {
			t.Errorf("%q should be invalid", n)
		}
	}
	if commap.DomainNode("Evil.Example.:443") != "domain:evil.example" {
		t.Fatal(commap.DomainNode("Evil.Example.:443"))
	}
}

func TestEnricherOnlyForURLs(t *testing.T) {
	e := commap.NewEnricher(4)
	v, err := e.Enrich(context.Background(), action.Action{Target: map[string]any{"url": "https://x"}}, control.State{})
	if err != nil || v.(map[string]any)["encoded_param_min"] != commap.EncodedParamFloor {
		t.Fatalf("%v %v", v, err)
	}
	if v, _ := e.Enrich(context.Background(), action.Action{Target: map[string]any{"domain": "x"}}, control.State{}); v != nil {
		t.Fatalf("context for an action without a URL: %v", v)
	}
}

func TestSummarizeQueryCarriesNoValuesAndFeedsDetection(t *testing.T) {
	val := strings.Repeat("QUJDRGVm9+", 30)
	ps := commap.SummarizeURL("https://collector.example.net/p.gif?id=7&d=" + val)
	if len(ps) != 1 {
		t.Fatalf("summary: %v", ps)
	}
	raw, _ := json.Marshal(ps)
	if strings.Contains(string(raw), "QUJD") {
		t.Fatalf("summary leaks the value: %s", raw)
	}
	var back []any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	got := commap.FindEncodedParams(map[string]any{"encoded_params": back}, 256)
	if len(got) != 1 || got[0].Name != "d" || got[0].Length != 300 {
		t.Fatalf("detection from summary: %v", got)
	}
	if got := commap.FindEncodedParams(map[string]any{"encoded_params": back}, 400); len(got) != 0 {
		t.Fatalf("threshold not applied: %v", got)
	}
	if commap.SummarizeRawQuery("q=hello&page=2") != nil {
		t.Fatal("plain query summarised")
	}
}

// Phase 5 review (map #1): agentgw passes the raw query (no "?"). A
// parameter value containing "://" or "?" must not make it look like a URL
// whose query is elsewhere.
func TestSummarizeRawQueryIgnoresURLsInValues(t *testing.T) {
	val := strings.Repeat("QUJDRGVm9+", 40)
	for _, q := range []string{
		"d=" + val,
		"d=" + val + "&r=https://example.com/",
		"d=" + val + "&r=https://example.com/?x=1",
	} {
		ps := commap.SummarizeRawQuery(q)
		got := commap.FindEncodedParams(map[string]any{"encoded_params": ps}, 256)
		if len(got) == 0 || got[0].Length != 400 {
			t.Errorf("%.40s...: %v", q, got)
		}
	}
}
