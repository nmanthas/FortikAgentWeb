package coverage_test

import (
	"context"
	"testing"

	"fortik/internal/coverage"
	"fortik/internal/netsuite"
	"fortik/internal/testutil"
)

// Every declaration states every dimension exactly once, and every claim of
// verification names its evidence: no silent or unbacked coverage.
func TestDeclarationsAreCompleteAndBacked(t *testing.T) {
	for _, d := range coverage.Declarations() {
		seen := map[string]int{}
		for _, c := range d.Capabilities {
			seen[c.Dimension]++
			switch c.Status {
			case coverage.VerifiedLive, coverage.VerifiedTest:
				if c.Evidence == "" {
					t.Errorf("%s.%s: %s without evidence", d.System, c.Dimension, c.Status)
				}
			case coverage.Implemented, coverage.Unsupported, coverage.NotBuilt, coverage.NotConfigured:
			default:
				t.Errorf("%s.%s: unknown status %q", d.System, c.Dimension, c.Status)
			}
		}
		for _, dim := range coverage.Dimensions {
			if seen[dim] != 1 {
				t.Errorf("%s: dimension %s declared %d times", d.System, dim, seen[dim])
			}
		}
		if len(seen) != len(coverage.Dimensions) {
			t.Errorf("%s: unknown dimension declared", d.System)
		}
	}
}

func TestClassifyNeverCreditsTestOnlyVerification(t *testing.T) {
	d := coverage.Declaration{Capabilities: []coverage.Capability{{Dimension: coverage.DimPreExec, Status: coverage.VerifiedTest}}}
	if cl, _ := coverage.Classify(d, true); cl != coverage.ClassUnknown {
		t.Fatalf("test-only pre-execution got class %s", cl)
	}
	d.Capabilities[0].Status = coverage.VerifiedLive
	if cl, _ := coverage.Classify(d, true); cl != coverage.ClassPrevented {
		t.Fatalf("live pre-execution: %s", cl)
	}
	if cl, _ := coverage.Classify(d, false); cl != coverage.ClassUnknown {
		t.Fatalf("not connected: %s", cl)
	}
	d.Capabilities = []coverage.Capability{{Dimension: coverage.DimSuspension, Status: coverage.VerifiedLive}}
	if cl, _ := coverage.Classify(d, true); cl != coverage.ClassContained {
		t.Fatalf("containment only: %s", cl)
	}
	d.Capabilities = []coverage.Capability{{Dimension: coverage.DimActivity, Status: coverage.VerifiedLive}}
	if cl, _ := coverage.Classify(d, true); cl != coverage.ClassObserved {
		t.Fatalf("observation only: %s", cl)
	}
}

func TestReportsFollowTheConnectedIntegrations(t *testing.T) {
	pool, _ := testutil.FortikDB(t)
	ctx := context.Background()
	svc := coverage.New(pool, coverage.Declarations(), func(s string) bool { return s == "claude_code" })
	class := func() map[string]string {
		rs, err := svc.Reports(ctx)
		if err != nil {
			t.Fatal(err)
		}
		m := map[string]string{}
		for _, r := range rs {
			m[r.System] = r.Class
		}
		return m
	}
	got := class()
	for sys, want := range map[string]string{"postgres": "D", "claude_code": "A", "agentgateway": "D", "google_workspace": "D", "netsuite": "D", "salesforce": "D"} {
		if got[sys] != want {
			t.Errorf("before connecting: %s class %s, want %s", sys, got[sys], want)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO integrations (key, system, status, updated_by) VALUES ('postgres:acme_prod', 'postgres', 'ok', 'test'),
		('google_workspace', 'google_workspace', 'ok', 'test')`); err != nil {
		t.Fatal(err)
	}
	got = class()
	if got["postgres"] != "A" {
		t.Errorf("postgres connected: %s", got["postgres"])
	}
	// Connected, but verified only against fakes: still D.
	if got["google_workspace"] != "D" {
		t.Errorf("google connected but unverified live: %s", got["google_workspace"])
	}
}

// Connector declarations (outside this package) obey the same rules.
func TestConnectorDeclarationsAreBacked(t *testing.T) {
	d := netsuite.Declaration()
	for _, c := range d.Capabilities {
		if (c.Status == coverage.VerifiedLive || c.Status == coverage.VerifiedTest) && c.Evidence == "" {
			t.Errorf("netsuite.%s without evidence", c.Dimension)
		}
		if c.Dimension == coverage.DimPreExec && c.Status == coverage.VerifiedLive {
			t.Error("netsuite pre-execution must not claim live verification without a real account")
		}
	}
	if cl, _ := coverage.Classify(d, true); cl != coverage.ClassUnknown {
		t.Errorf("netsuite verified only against a fake must be class D, got %s", cl)
	}
	got := coverage.Replace(coverage.Declarations(), d)
	n := 0
	for _, x := range got {
		if x.System == "netsuite" {
			n++
			if x.Milestone != "" {
				t.Error("placeholder not replaced")
			}
		}
	}
	if n != 1 {
		t.Fatalf("%d netsuite declarations", n)
	}
}
