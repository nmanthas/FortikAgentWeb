// Package replay is the policy regression gate (plan: "10,000 recorded
// actions replayed through /decide; any class change versus the last release
// blocks the merge").
//
// The corpus (testdata/replay/corpus.jsonl.gz) holds full policy inputs, as
// the decide service builds them, with the result the policy gave at the last
// release. Run evaluates every input with the bundle in the tree and reports
// each difference; a class, decision, rule or step-down change is a failure
// (go test ./internal/replay, part of make ci). Update rewrites the expected
// results after a reviewed policy change and prints what it accepts.
//
// Inputs come from real traffic: FORTIK_POLICY_CAPTURE records every input
// the engine evaluates while the test suites and the phase demos run (the
// proxy, gateways, hook, swarm, memory...). Build deduplicates them, adds
// variants that exercise the gates (every control level, observe mode,
// unregistered) and selects the corpus deterministically.
package replay

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"

	"fortik/internal/control"
	"fortik/internal/policy"
)

// Record is one replayed decision.
type Record struct {
	ID     string       `json:"id"`
	Input  policy.Input `json:"input"`
	Expect Expect       `json:"expect"`
}

// Expect is the part of a result the gate compares.
type Expect struct {
	Class             string   `json:"class"`
	Decision          string   `json:"decision"`
	RuleID            string   `json:"rule_id"`
	ApprovalsRequired int      `json:"approvals_required,omitempty"`
	LadderTo          string   `json:"ladder_to,omitempty"`
	ObservedDecision  string   `json:"observed_decision,omitempty"`
	Matched           []string `json:"matched,omitempty"` // rule ids, sorted (informational)
}

// ExpectOf extracts the compared fields of a result.
func ExpectOf(r policy.Result) Expect {
	e := Expect{Class: string(r.Class), Decision: string(r.Decision), RuleID: r.RuleID, ApprovalsRequired: r.ApprovalsRequired}
	if r.LadderChange != nil {
		e.LadderTo = r.LadderChange.To
	}
	if r.Observed != nil {
		e.ObservedDecision = string(r.Observed.Decision)
	}
	seen := map[string]bool{}
	for _, m := range r.Matched {
		if !seen[m.RuleID] {
			seen[m.RuleID] = true
			e.Matched = append(e.Matched, m.RuleID)
		}
	}
	sort.Strings(e.Matched)
	return e
}

// Diff is one record whose result changed.
type Diff struct {
	ID      string `json:"id"`
	Summary string `json:"summary"` // system verb agent level
	Got     Expect `json:"got"`
	Want    Expect `json:"want"`
	// Breaking: class, decision, rule, approvals, step-down or observed
	// decision changed (blocks the merge). Otherwise only the matched set
	// changed (reported, not blocking).
	Breaking bool   `json:"breaking"`
	Class    bool   `json:"class_changed"`
	Err      string `json:"error,omitempty"`
}

// Report is the outcome of a run.
type Report struct {
	Records  int    `json:"records"`
	Breaking int    `json:"breaking"`
	Classes  int    `json:"class_changes"`
	Matched  int    `json:"matched_only"`
	Errors   int    `json:"errors"`
	Diffs    []Diff `json:"diffs"`
	Policy   string `json:"policy_version"`
}

// OK reports whether the run passes the gate.
func (r Report) OK() bool { return r.Breaking == 0 && r.Errors == 0 }

// Evaluator is the policy engine (policy.Engine satisfies it).
type Evaluator interface {
	Eval(ctx context.Context, in policy.Input) (policy.Result, error)
	Version() string
}

// Run evaluates every record and compares it with its expectation.
func Run(ctx context.Context, eng Evaluator, recs []Record) Report {
	rep := Report{Records: len(recs), Policy: eng.Version()}
	for _, rec := range recs {
		res, err := eng.Eval(ctx, rec.Input)
		if err != nil {
			rep.Errors++
			rep.Diffs = append(rep.Diffs, Diff{ID: rec.ID, Summary: summary(rec.Input), Want: rec.Expect, Breaking: true, Err: err.Error()})
			continue
		}
		got := ExpectOf(res)
		if equal(got, rec.Expect) {
			continue
		}
		d := Diff{ID: rec.ID, Summary: summary(rec.Input), Got: got, Want: rec.Expect, Class: got.Class != rec.Expect.Class}
		d.Breaking = !behaviourEqual(got, rec.Expect)
		switch {
		case d.Class:
			rep.Classes++
			rep.Breaking++
		case d.Breaking:
			rep.Breaking++
		default:
			rep.Matched++
		}
		rep.Diffs = append(rep.Diffs, d)
	}
	return rep
}

func behaviourEqual(a, b Expect) bool {
	return a.Class == b.Class && a.Decision == b.Decision && a.RuleID == b.RuleID && a.ApprovalsRequired == b.ApprovalsRequired &&
		a.LadderTo == b.LadderTo && a.ObservedDecision == b.ObservedDecision
}

func equal(a, b Expect) bool { return behaviourEqual(a, b) && slices.Equal(a.Matched, b.Matched) }

func summary(in policy.Input) string {
	return fmt.Sprintf("%s %s agent=%s level=%s registered=%v enforcement=%s", in.Action.System, in.Action.Verb, in.Action.AgentID,
		in.Agent.Level, in.Agent.Registered, orDefault(in.Enforcement, "enforce"))
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// Update re-evaluates every record and stores the current results as the new
// expectations; it returns the report of what changed (the review artifact).
func Update(ctx context.Context, eng Evaluator, recs []Record) ([]Record, Report, error) {
	rep := Run(ctx, eng, recs)
	if rep.Errors > 0 {
		return nil, rep, fmt.Errorf("replay: %d inputs fail to evaluate: fix the policy before updating", rep.Errors)
	}
	out := make([]Record, len(recs))
	for i, rec := range recs {
		res, err := eng.Eval(ctx, rec.Input)
		if err != nil {
			return nil, rep, err
		}
		rec.Expect = ExpectOf(res)
		out[i] = rec
	}
	return out, rep, nil
}

// --- corpus file -------------------------------------------------------------

// Load reads a corpus (gzip JSON lines).
func Load(path string) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("replay corpus %s: %w", path, err)
	}
	var out []Record
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	for sc.Scan() {
		if len(strings.TrimSpace(sc.Text())) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return nil, fmt.Errorf("replay corpus %s line %d: %w", path, len(out)+1, err)
		}
		out = append(out, r)
	}
	return out, sc.Err()
}

// Write stores a corpus deterministically (records sorted by id, no gzip
// timestamp), so an unchanged corpus is byte-identical.
func Write(path string, recs []Record) error {
	sorted := slices.Clone(recs)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	zw, _ := gzip.NewWriterLevel(f, gzip.BestCompression)
	bw := bufio.NewWriter(zw)
	for _, r := range sorted {
		b, err := json.Marshal(r)
		if err != nil {
			f.Close()
			return err
		}
		bw.Write(b)
		bw.WriteByte('\n')
	}
	if err := bw.Flush(); err != nil {
		f.Close()
		return err
	}
	if err := zw.Close(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// --- building a corpus from captured inputs -------------------------------------

// ReadCapture reads FORTIK_POLICY_CAPTURE files (one Input per line);
// malformed lines are skipped.
func ReadCapture(paths ...string) ([]policy.Input, error) {
	var out []policy.Input
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
		for sc.Scan() {
			var in policy.Input
			if json.Unmarshal(sc.Bytes(), &in) == nil && in.Action.AgentID != "" {
				out = append(out, in)
			}
		}
		err = sc.Err()
		f.Close()
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
	}
	return out, nil
}

// ID is the content hash of an input (12 bytes, hex).
func ID(in policy.Input) string {
	b, _ := json.Marshal(in)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:12])
}

// Variants returns the base input plus copies that exercise the gates: every
// control level, observe mode, and unregistered. Duplicates are removed by
// the caller (by ID).
func Variants(in policy.Input) []policy.Input {
	out := []policy.Input{in}
	for _, l := range []control.Level{control.Full, control.Supervised, control.ReadOnly, control.Isolated, control.Quarantined, control.Killed} {
		v := in
		v.Agent.Level, v.Agent.LevelName = l, l.String()
		out = append(out, v)
	}
	o := in
	o.Enforcement = policy.ObserveMode
	out = append(out, o)
	u := in
	u.Agent.Registered = false
	out = append(out, u)
	return out
}

// Build turns captured inputs into a corpus of n records: deduplicated,
// expanded with Variants, evaluated, then selected round-robin over the
// (system, verb, class, decision) strata in ID order, so every kind of
// decision is represented and the selection is reproducible.
func Build(ctx context.Context, eng Evaluator, captured []policy.Input, n int) ([]Record, error) {
	seen := map[string]bool{}
	var cands []Record
	add := func(in policy.Input) {
		id := ID(in)
		if seen[id] {
			return
		}
		seen[id] = true
		cands = append(cands, Record{ID: id, Input: in})
	}
	for _, in := range captured {
		add(in)
	}
	base := len(cands)
	for i := 0; i < base; i++ {
		for _, v := range Variants(cands[i].Input)[1:] {
			add(v)
		}
	}
	strata := map[string][]Record{}
	var keys []string
	for _, c := range cands {
		res, err := eng.Eval(ctx, c.Input)
		if err != nil {
			continue // inputs the current bundle cannot evaluate are not baselines
		}
		c.Expect = ExpectOf(res)
		k := strings.Join([]string{c.Input.Action.System, string(c.Input.Action.Verb), c.Expect.Class, c.Expect.Decision, c.Expect.RuleID}, "|")
		if _, ok := strata[k]; !ok {
			keys = append(keys, k)
		}
		strata[k] = append(strata[k], c)
	}
	sort.Strings(keys)
	for _, k := range keys {
		sort.Slice(strata[k], func(i, j int) bool { return strata[k][i].ID < strata[k][j].ID })
	}
	var out []Record
	for round := 0; len(out) < n; round++ {
		added := false
		for _, k := range keys {
			if round < len(strata[k]) && len(out) < n {
				out = append(out, strata[k][round])
				added = true
			}
		}
		if !added {
			break
		}
	}
	return out, nil
}
