package policy_test

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/open-policy-agent/opa/v1/tester"

	"fortik/internal/action"
	"fortik/internal/control"
	"fortik/internal/policy"
)

func bundleDir() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..", "policies")
}

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// TestRegoSuite runs every *_test.rego (the OPA test framework) as part of
// `go test`, so CI needs only Go.
func TestRegoSuite(t *testing.T) {
	ctx := context.Background()
	results, err := tester.Run(ctx, bundleDir())
	if err != nil {
		t.Fatalf("rego tests: %v", err)
	}
	if len(results) < 50 {
		t.Fatalf("expected the full rego suite, got %d tests", len(results))
	}
	for _, r := range results {
		if r.Fail || r.Error != nil {
			t.Errorf("%s.%s failed: %v", r.Package, r.Name, r.Error)
		}
	}
}

func input(level control.Level, stype string, verb action.Verb) policy.Input {
	return policy.Input{
		Action: action.Action{AgentID: "a", System: "postgres", Verb: verb,
			Target: map[string]any{"statement_type": stype, "environment": "prod", "tables": []string{"public.orders"}}},
		Agent: control.State{AgentID: "a", Registered: true, Level: level},
	}
}

func TestEngineEval(t *testing.T) {
	e, err := policy.NewEngine(context.Background(), bundleDir(), quiet)
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Eval(context.Background(), input(control.Full, "DROP_TABLE", action.VerbDelete))
	if err != nil {
		t.Fatal(err)
	}
	if r.Class != policy.Red || r.Decision != policy.Hold || r.RuleID != "POL-101" || r.LadderChange == nil || r.LadderChange.To != "READ_ONLY" {
		t.Fatalf("got %+v", r)
	}
	if !strings.HasPrefix(r.PolicyVersion, "sha256:") {
		t.Fatalf("policy version %q", r.PolicyVersion)
	}
}

func TestEngineDeterministic(t *testing.T) {
	e, _ := policy.NewEngine(context.Background(), bundleDir(), quiet)
	in := input(control.Full, "DELETE", action.VerbDelete)
	first, _ := e.Eval(context.Background(), in)
	for i := 0; i < 50; i++ {
		r, _ := e.Eval(context.Background(), in)
		if r.Class != first.Class || r.Decision != first.Decision || r.RuleID != first.RuleID || r.Reason != first.Reason {
			t.Fatal("non-deterministic result")
		}
	}
}

func copyBundle(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.Walk(bundleDir(), func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(bundleDir(), p)
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func TestBrokenBundleRejectedAtStartup(t *testing.T) {
	dir := copyBundle(t)
	_ = os.WriteFile(filepath.Join(dir, "fortik", "rules", "broken.rego"), []byte("package fortik.rules\nthis is not rego"), 0o644)
	if _, err := policy.NewEngine(context.Background(), dir, quiet); err == nil {
		t.Fatal("broken bundle must not load")
	}
}

func TestHotReloadKeepsOldBundleOnError(t *testing.T) {
	dir := copyBundle(t)
	e, err := policy.NewEngine(context.Background(), dir, quiet)
	if err != nil {
		t.Fatal(err)
	}
	v1 := e.Version()
	reloads := make(chan error, 4)
	e.OnReload = func(_ string, err error) { reloads <- err }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.Watch(ctx, 20*time.Millisecond)

	// 1) a broken edit is rejected; the old bundle keeps deciding.
	bad := filepath.Join(dir, "fortik", "rules", "zz.rego")
	_ = os.WriteFile(bad, []byte("package fortik.rules\nfindings contains x if {"), 0o644)
	if err := <-reloads; err == nil {
		t.Fatal("broken reload reported success")
	}
	if e.Version() != v1 {
		t.Fatal("broken bundle replaced the running one")
	}
	if r, err := e.Eval(context.Background(), input(control.Full, "DROP_TABLE", action.VerbDelete)); err != nil || r.RuleID != "POL-101" {
		t.Fatalf("old bundle stopped working: %v %+v", err, r)
	}

	// 2) a valid edit (tighten: SELECT on prod becomes yellow+hold) takes effect.
	good := `package fortik.rules
findings contains {"rule_id": "POL-999", "class": "yellow", "reason": "test rule", "hold": true} if {
	act.system == "postgres"
	object.get(tgt, "statement_type", "") == "SELECT"
}`
	_ = os.WriteFile(bad, []byte(good), 0o644)
	if err := <-reloads; err != nil {
		t.Fatalf("valid reload failed: %v", err)
	}
	if e.Version() == v1 {
		t.Fatal("version did not change")
	}
	r, _ := e.Eval(context.Background(), input(control.Full, "SELECT", action.VerbRead))
	if r.RuleID != "POL-999" || r.Decision != policy.Hold {
		t.Fatalf("reloaded rule not applied: %+v", r)
	}
}

func BenchmarkEvalGreen(b *testing.B) {
	e, _ := policy.NewEngine(context.Background(), bundleDir(), quiet)
	in := input(control.Full, "SELECT", action.VerbRead)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.Eval(context.Background(), in); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEvalRed(b *testing.B) {
	e, _ := policy.NewEngine(context.Background(), bundleDir(), quiet)
	in := input(control.Full, "DROP_TABLE", action.VerbDelete)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.Eval(context.Background(), in); err != nil {
			b.Fatal(err)
		}
	}
}
