package replay_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"fortik/internal/policy"
	"fortik/internal/replay"
)

func root() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..")
}

func engine(t *testing.T) *policy.Engine {
	t.Helper()
	eng, err := policy.NewEngine(context.Background(), filepath.Join(root(), "policies"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

// The merge gate: every recorded input must get the result it got at the last
// release. A class, decision, rule or step-down change fails; review it, then
// run `fortik replay update` and commit the corpus with the policy change.
func TestReplayCorpusUnchanged(t *testing.T) {
	recs, err := replay.Load(filepath.Join(root(), "testdata", "replay", "corpus.jsonl.gz"))
	if err != nil {
		t.Fatalf("replay corpus missing: %v", err)
	}
	if len(recs) < 10000 {
		t.Fatalf("replay corpus has %d records; the plan requires 10,000", len(recs))
	}
	rep := replay.Run(context.Background(), engine(t), recs)
	for i, d := range rep.Diffs {
		if i == 30 {
			t.Logf("... %d more", len(rep.Diffs)-30)
			break
		}
		t.Logf("%s %s: want %+v got %+v err=%s", d.ID, d.Summary, d.Want, d.Got, d.Err)
	}
	if !rep.OK() {
		t.Fatalf("policy regression: %d breaking change(s), %d class change(s), %d error(s) in %d records",
			rep.Breaking, rep.Classes, rep.Errors, rep.Records)
	}
	if rep.Matched > 0 {
		t.Logf("%d records changed only their matched-rule list (not blocking)", rep.Matched)
	}
}

// The gate notices a class change and a decision change, and Update accepts
// them; Write is byte-for-byte deterministic.
func TestGateDetectsChangesAndUpdateAccepts(t *testing.T) {
	recs, err := replay.Load(filepath.Join(root(), "testdata", "replay", "corpus.jsonl.gz"))
	if err != nil {
		t.Fatal(err)
	}
	recs = recs[:200]
	eng := engine(t)
	tampered := append([]replay.Record(nil), recs...)
	tampered[0].Expect.Class = "green"
	if tampered[0].Expect.Class == recs[0].Expect.Class {
		tampered[0].Expect.Class = "red"
	}
	tampered[1].Expect.Decision = "deny"
	if recs[1].Expect.Decision == "deny" {
		tampered[1].Expect.Decision = "allow"
	}
	tampered[2].Expect.Matched = append(tampered[2].Expect.Matched, "POL-999")
	rep := replay.Run(context.Background(), eng, tampered)
	if rep.OK() || rep.Classes != 1 || rep.Breaking != 2 || rep.Matched != 1 {
		t.Fatalf("report %+v", rep)
	}
	fixed, _, err := replay.Update(context.Background(), eng, tampered)
	if err != nil {
		t.Fatal(err)
	}
	if r := replay.Run(context.Background(), eng, fixed); !r.OK() || len(r.Diffs) != 0 {
		t.Fatalf("after update: %+v", r)
	}
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.gz"), filepath.Join(dir, "b.gz")
	if err := replay.Write(a, fixed); err != nil {
		t.Fatal(err)
	}
	rev := append([]replay.Record(nil), fixed...)
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	if err := replay.Write(b, rev); err != nil {
		t.Fatal(err)
	}
	ba, _ := os.ReadFile(a)
	bb, _ := os.ReadFile(b)
	if !bytes.Equal(ba, bb) {
		t.Fatal("corpus writes are not deterministic")
	}
}
