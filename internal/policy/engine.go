package policy

import (
	"bytes"

	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

// Query is the single entry point of the bundle.
const Query = "data.fortik.decide.result"

// Engine evaluates the embedded OPA policy bundle. Swapping bundles is atomic:
// a bundle that fails to compile never replaces the running one.
type Engine struct {
	dir     string
	log     *slog.Logger
	current atomic.Pointer[compiled]
	// OnReload, when set, is called after every reload attempt (for the Diary).
	OnReload func(version string, err error)
}

type compiled struct {
	query   rego.PreparedEvalQuery
	version string
	hash    string // full content hash of the compiled bundle
}

// NewEngine compiles the bundle in dir (files *.rego and data.json; *_test.rego excluded).
func NewEngine(ctx context.Context, dir string, log *slog.Logger) (*Engine, error) {
	e := &Engine{dir: dir, log: log}
	c, err := compile(ctx, dir)
	if err != nil {
		return nil, err
	}
	e.current.Store(c)
	return e, nil
}

// Version is a content hash of the loaded bundle ("sha256:<12 hex>").
func (e *Engine) Version() string { return e.current.Load().version }

// Eval runs the policy. Any error (or an unexpected/empty result) is returned
// as an error; the caller must fail closed.
func (e *Engine) Eval(ctx context.Context, in Input) (Result, error) {
	c := e.current.Load()
	raw, err := toValue(in)
	if err != nil {
		return Result{}, fmt.Errorf("policy input: %w", err)
	}
	rs, err := c.query.Eval(ctx, rego.EvalParsedInput(raw))
	if err != nil {
		return Result{}, fmt.Errorf("policy eval: %w", err)
	}
	if len(rs) != 1 || len(rs[0].Expressions) != 1 {
		return Result{}, errors.New("policy eval: no result (bundle produced no decision)")
	}
	b, err := json.Marshal(rs[0].Expressions[0].Value)
	if err != nil {
		return Result{}, fmt.Errorf("policy result: %w", err)
	}
	var r Result
	if err := json.Unmarshal(b, &r); err != nil {
		return Result{}, fmt.Errorf("policy result: %w", err)
	}
	if err := r.validate(); err != nil {
		return Result{}, err
	}
	r.PolicyVersion = c.version
	return r, nil
}

func (r *Result) validate() error {
	switch r.Class {
	case Green, Yellow, Red:
	default:
		return fmt.Errorf("policy result: invalid class %q", r.Class)
	}
	switch r.Decision {
	case Allow, AllowReduced, Hold, Deny:
	default:
		return fmt.Errorf("policy result: invalid decision %q", r.Decision)
	}
	if r.RuleID == "" {
		return errors.New("policy result: missing rule_id")
	}
	// Defence in depth: the bundle must never let red run.
	if r.Class == Red && r.Decision.Executes() {
		return fmt.Errorf("policy result: red class with executing decision %q", r.Decision)
	}
	if r.Decision == AllowReduced && len(r.ReducedForm) == 0 {
		return errors.New("policy result: allow_reduced without reduced_form")
	}
	if r.Class == Yellow && r.Decision == Allow && r.GrantID == "" {
		return errors.New("policy result: yellow must run reduced, be held, or be denied — never plain allow")
	}
	if r.Decision != AllowReduced && len(r.ReducedForm) > 0 {
		return fmt.Errorf("policy result: reduced_form present with decision %q", r.Decision)
	}
	if r.LadderChange != nil {
		switch r.LadderChange.To {
		case "FULL", "SUPERVISED", "READ_ONLY", "ISOLATED", "QUARANTINED", "KILLED":
		default:
			return fmt.Errorf("policy result: ladder_change to unknown level %q", r.LadderChange.To)
		}
	}
	if r.GrantID != "" && (r.Class != Yellow || r.Decision != Allow) {
		return fmt.Errorf("policy result: grant_id only valid on an allowed yellow (got %s/%s)", r.Class, r.Decision)
	}
	if r.ApprovalsRequired != 0 && (r.Decision != Hold || r.ApprovalsRequired < 1 || r.ApprovalsRequired > 5) {
		return fmt.Errorf("policy result: approvals_required %d only valid (1-5) on a hold (got %s)", r.ApprovalsRequired, r.Decision)
	}
	if r.LadderChange != nil && r.Class != Red {
		return fmt.Errorf("policy result: ladder_change on a %s result", r.Class)
	}
	return nil
}

// Watch polls the bundle directory and hot-reloads on change until ctx ends.
func (e *Engine) Watch(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	// Compare against what is actually compiled (not a fresh scan), so an
	// edit landing before the first tick is never mistaken for the baseline.
	last := e.current.Load().hash
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		h, err := bundleHash(e.dir)
		if err != nil || h == last {
			continue
		}
		last = h
		c, err := compile(ctx, e.dir)
		if err != nil {
			e.log.Error("policy reload failed; keeping current bundle", "err", err, "current", e.Version())
		} else {
			e.current.Store(c)
			e.log.Info("policy bundle reloaded", "version", c.version)
		}
		if e.OnReload != nil {
			v := e.Version()
			e.OnReload(v, err)
		}
	}
}

func compile(ctx context.Context, dir string) (*compiled, error) {
	h, err := bundleHash(dir)
	if err != nil {
		return nil, err
	}
	pq, err := rego.New(
		rego.Query(Query),
		rego.Load([]string{dir}, func(abspath string, info fs.FileInfo, depth int) bool {
			// true = skip
			if info.IsDir() {
				return false
			}
			name := info.Name()
			if strings.HasSuffix(name, "_test.rego") {
				return true
			}
			return !(strings.HasSuffix(name, ".rego") || name == "data.json")
		}),
		rego.StrictBuiltinErrors(true),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("compile policy bundle %s: %w", dir, err)
	}
	return &compiled{query: pq, version: "sha256:" + h[:12], hash: h}, nil
}

// bundleHash hashes every non-test policy file (path + content).
func bundleHash(dir string) (string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		n := d.Name()
		if !d.IsDir() && !strings.HasSuffix(n, "_test.rego") && (strings.HasSuffix(n, ".rego") || n == "data.json") {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("scan policy bundle: %w", err)
	}
	if len(files) == 0 {
		return "", fmt.Errorf("policy bundle %s has no .rego files", dir)
	}
	sort.Strings(files)
	h := sha256.New()
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", err
		}
		rel, _ := filepath.Rel(dir, f)
		fmt.Fprintf(h, "%s\x00%d\x00", rel, len(b))
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// toValue converts the Input via its JSON form (so json tags are the contract)
// keeping numbers exact.
func toValue(in Input) (ast.Value, error) {
	b, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return ast.InterfaceToValue(v)
}
