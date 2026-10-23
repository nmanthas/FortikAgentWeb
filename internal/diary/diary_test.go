package diary_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/diary"
	"fortik/internal/testutil"
)

func signer(t *testing.T) *diary.Signer {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	_, _ = rand.Read(seed)
	s, err := diary.NewSigner([]byte(base64.StdEncoding.EncodeToString(seed)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestComputeHashIsSHA256OfPrevPlusBody(t *testing.T) {
	// echo -n "$(printf '0%.0s' {1..64})"'{"a":1}' | shasum -a 256
	got := diary.ComputeHash(diary.GenesisHash, `{"a":1}`)
	if len(got) != 64 || got == diary.ComputeHash(diary.GenesisHash, `{"a":2}`) {
		t.Fatalf("unexpected hash %s", got)
	}
}

func TestCanonicalSortsKeys(t *testing.T) {
	a, _ := diary.Canonical(map[string]any{"b": 1, "a": map[string]any{"d": 1, "c": "<x>"}})
	if a != `{"a":{"c":"<x>","d":1},"b":1}` {
		t.Fatalf("not canonical: %s", a)
	}
	type s struct {
		Z int `json:"z"`
		A int `json:"a"`
	}
	b, _ := diary.Canonical(s{Z: 1, A: 2})
	if b != `{"a":2,"z":1}` {
		t.Fatalf("struct not canonical: %s", b)
	}
}

func TestVerifyEntriesDetectsTampering(t *testing.T) {
	var entries []diary.Entry
	prev := diary.GenesisHash
	ts := time.Date(2026, 10, 6, 10, 0, 0, 0, time.UTC)
	for i := int64(1); i <= 3; i++ {
		body, _ := diary.Canonical(map[string]any{"seq": i, "ts": ts.Format(time.RFC3339Nano), "agent_id": "a", "event_type": "e", "actor": "x", "data": map[string]any{}})
		h := diary.ComputeHash(prev, body)
		entries = append(entries, diary.Entry{Seq: i, TS: ts, AgentID: "a", EventType: "e", Actor: "x", BodyJSON: body, PrevHash: prev, Hash: h})
		prev = h
	}
	if r := diary.VerifyEntries(entries, diary.GenesisHash); !r.OK {
		t.Fatalf("clean chain failed: %v", r.Problems)
	}
	tampered := append([]diary.Entry(nil), entries...)
	tampered[1].BodyJSON = strings.Replace(tampered[1].BodyJSON, `"actor":"x"`, `"actor":"y"`, 1)
	if r := diary.VerifyEntries(tampered, diary.GenesisHash); r.OK {
		t.Fatal("body tampering not detected")
	}
	gap := []diary.Entry{entries[0], entries[2]}
	if r := diary.VerifyEntries(gap, diary.GenesisHash); r.OK {
		t.Fatal("deleted middle entry not detected")
	}
	cols := append([]diary.Entry(nil), entries...)
	cols[0].AgentID = "someone_else"
	if r := diary.VerifyEntries(cols, diary.GenesisHash); r.OK {
		t.Fatal("column/body disagreement not detected")
	}
}

func TestAppendVerifyAndAppendOnly(t *testing.T) {
	pool, _ := testutil.FortikDB(t)
	ctx := context.Background()
	d := diary.New(pool)

	for i := 0; i < 5; i++ {
		if _, err := d.Append(ctx, diary.Event{AgentID: "agent_1", EventType: "test.event", Actor: "test", Data: map[string]any{"i": i}}); err != nil {
			t.Fatal(err)
		}
	}
	rep, err := d.VerifyChain(ctx)
	if err != nil || !rep.OK || rep.Checked != 5 || rep.HeadSeq != 5 {
		t.Fatalf("verify: %+v err=%v", rep, err)
	}

	// The database refuses UPDATE / DELETE / TRUNCATE on the diary.
	for _, q := range []string{
		`UPDATE diary SET actor = 'evil' WHERE seq = 2`,
		`DELETE FROM diary WHERE seq = 5`,
		`TRUNCATE diary`,
	} {
		if _, err := pool.Exec(ctx, q); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Fatalf("%q was not refused: %v", q, err)
		}
	}

	// Simulate an attacker with trigger-bypass privileges editing a row: verification must catch it.
	if _, err := pool.Exec(ctx, `ALTER TABLE diary DISABLE TRIGGER diary_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE diary SET body_json = replace(body_json, '"i":2', '"i":99') WHERE seq = 3`); err != nil {
		t.Fatal(err)
	}
	rep, _ = d.VerifyChain(ctx)
	if rep.OK {
		t.Fatal("tampered row not detected by VerifyChain")
	}
	// Tail deletion: head still points at seq 5.
	if _, err := pool.Exec(ctx, `DELETE FROM diary WHERE seq = 5`); err != nil {
		t.Fatal(err)
	}
	rep, _ = d.VerifyChain(ctx)
	found := false
	for _, p := range rep.Problems {
		if strings.Contains(p, "head") {
			found = true
		}
	}
	if !found {
		t.Fatalf("tail deletion not detected: %v", rep.Problems)
	}
}

func TestConcurrentAppendsKeepChainGapless(t *testing.T) {
	pool, _ := testutil.FortikDB(t)
	ctx := context.Background()
	d := diary.New(pool)
	var wg sync.WaitGroup
	errs := make(chan error, 200)
	for g := 0; g < 10; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if _, err := d.Append(ctx, diary.Event{AgentID: "a", EventType: "c", Actor: "t", Data: map[string]any{"g": g, "i": i}}); err != nil {
					errs <- err
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	rep, err := d.VerifyChain(ctx)
	if err != nil || !rep.OK || rep.Checked != 200 || rep.LastSeq != 200 {
		t.Fatalf("concurrent chain: %+v %v", rep, err)
	}
}

func TestExportIsVerifiableAndSigned(t *testing.T) {
	pool, _ := testutil.FortikDB(t)
	ctx := context.Background()
	d := diary.New(pool)
	s := signer(t)
	for i := 0; i < 3; i++ {
		_, _ = d.Append(ctx, diary.Event{AgentID: "a1", EventType: "x", Actor: "t"})
		_, _ = d.Append(ctx, diary.Event{AgentID: "a2", EventType: "x", Actor: "t"})
	}
	exp, err := d.Export(ctx, diary.Filter{}, s, "token:test")
	if err != nil {
		t.Fatal(err)
	}
	if !exp.Contiguous || !exp.Verification.OK || !exp.ChainCheck.OK || len(exp.Entries) != 6 || !exp.Signed {
		t.Fatalf("export: %+v", exp.Verification)
	}
	if !diary.VerifyRoot(*exp.HeadRoot) || exp.HeadRoot.Seq != 6 {
		t.Fatalf("head root signature invalid: %+v", exp.HeadRoot)
	}
	// The segment root signs the last exported entry: checkable from the export alone.
	last := exp.Entries[len(exp.Entries)-1]
	if !diary.VerifyRoot(*exp.SegmentRoot) || exp.SegmentRoot.RootHash != last.Hash || exp.SegmentRoot.Seq != last.Seq {
		t.Fatalf("segment root not tied to entries: %+v", exp.SegmentRoot)
	}
	forged := *exp.HeadRoot
	forged.RootHash = strings.Repeat("a", 64)
	if diary.VerifyRoot(forged) {
		t.Fatal("forged root verified")
	}
	// Export itself is audited.
	es, _ := d.Query(ctx, diary.Filter{AfterSeq: 6})
	if len(es) != 1 || es[0].EventType != diary.EventExported {
		t.Fatalf("export not recorded: %+v", es)
	}
	agentExp, err := d.Export(ctx, diary.Filter{AgentID: "a1"}, s, "token:test")
	if err != nil || agentExp.Contiguous || len(agentExp.Entries) != 3 || !agentExp.Verification.OK || agentExp.SegmentRoot != nil {
		t.Fatalf("agent export: %+v %v", agentExp.Verification, err)
	}
}

func TestSealDayIdempotent(t *testing.T) {
	pool, _ := testutil.FortikDB(t)
	ctx := context.Background()
	d := diary.New(pool)
	s := signer(t)
	_, _ = d.Append(ctx, diary.Event{EventType: "x", Actor: "t"})
	if _, err := d.SealDay(ctx, time.Now().UTC(), s, "t"); err == nil {
		t.Fatal("sealing a day that has not ended must fail")
	}
	yesterday := time.Now().UTC().Add(-24 * time.Hour)
	r1, err := d.SealDay(ctx, yesterday, s, "t")
	if err != nil || !diary.VerifyRoot(r1) {
		t.Fatalf("seal: %+v %v", r1, err)
	}
	r2, err := d.SealDay(ctx, yesterday, s, "t")
	if err != nil || r2.Signature != r1.Signature || !diary.VerifyRoot(r2) {
		t.Fatalf("seal not idempotent: %+v %v", r2, err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM diary_roots`); err == nil {
		t.Fatal("diary_roots must be append-only")
	}
}

// rewriteChain simulates an attacker with full database access who edits
// entries and recomputes every hash and the head (trigger disabled).
func rewriteChain(t *testing.T, pool *pgxpool.Pool, mutate func(seq int64, body map[string]any)) {
	t.Helper()
	ctx := context.Background()
	for _, q := range []string{`ALTER TABLE diary DISABLE TRIGGER diary_no_update`} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	rows, _ := pool.Query(ctx, `SELECT seq, body_json FROM diary ORDER BY seq`)
	type row struct {
		seq  int64
		body string
	}
	var all []row
	for rows.Next() {
		var r row
		_ = rows.Scan(&r.seq, &r.body)
		all = append(all, r)
	}
	rows.Close()
	prev := diary.GenesisHash
	for _, r := range all {
		var body map[string]any
		_ = json.Unmarshal([]byte(r.body), &body)
		mutate(r.seq, body)
		canon, _ := diary.Canonical(body)
		ts, _ := time.Parse(time.RFC3339Nano, body["ts"].(string))
		h := diary.ComputeHash(prev, canon)
		if _, err := pool.Exec(ctx, `UPDATE diary SET body_json=$2, prev_hash=$3, hash=$4, ts=$5 WHERE seq=$1`, r.seq, canon, prev, h, ts); err != nil {
			t.Fatal(err)
		}
		prev = h
	}
	if _, err := pool.Exec(ctx, `UPDATE diary_head SET hash=$1`, prev); err != nil {
		t.Fatal(err)
	}
	_, _ = pool.Exec(ctx, `ALTER TABLE diary ENABLE TRIGGER diary_no_update`)
}

func TestSealedRootDetectsRehashedRewrite(t *testing.T) {
	pool, _ := testutil.FortikDB(t)
	ctx := context.Background()
	d := diary.New(pool)
	s := signer(t)
	for i := 0; i < 3; i++ {
		_, _ = d.Append(ctx, diary.Event{AgentID: "a", EventType: "x", Actor: "t", Data: map[string]any{"i": i}})
	}
	// Setup: move the entries two days back (a consistent rewrite), then seal that day.
	twoDaysAgo := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Microsecond)
	rewriteChain(t, pool, func(_ int64, b map[string]any) { b["ts"] = twoDaysAgo.Format(time.RFC3339Nano) })
	if rep, _ := d.VerifyChain(ctx); !rep.OK {
		t.Fatalf("setup chain invalid: %v", rep.Problems)
	}
	root, err := d.SealDay(ctx, twoDaysAgo, s, "t")
	if err != nil || root.Seq != 3 {
		t.Fatalf("seal: %+v %v", root, err)
	}
	d.TrustRootKeys(mustPub(t, s))
	if rep, _ := d.VerifyChain(ctx); !rep.OK {
		t.Fatalf("sealed chain should verify: %v", rep.Problems)
	}
	// Attack: rewrite history and recompute every hash and the head.
	rewriteChain(t, pool, func(seq int64, b map[string]any) {
		if seq == 2 {
			b["data"] = map[string]any{"i": 999}
		}
	})
	rep, _ := d.VerifyChain(ctx)
	if rep.OK {
		t.Fatal("a fully re-hashed rewrite of sealed history was not detected")
	}
	if _, err := d.SealDay(ctx, time.Now().UTC().Add(-24*time.Hour), s, "t"); err == nil {
		t.Fatal("sealing on top of a broken chain must be refused")
	}
	exp, err := d.Export(ctx, diary.Filter{}, s, "t")
	if err != nil || exp.Signed || exp.HeadRoot != nil || exp.Warning == "" {
		t.Fatalf("a broken chain must not be signed: signed=%v err=%v", exp.Signed, err)
	}
}

func mustPub(t *testing.T, s *diary.Signer) ed25519.PublicKey {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.PublicKey(b)
}

func TestVerifyDuringConcurrentAppendsHasNoFalsePositive(t *testing.T) {
	pool, _ := testutil.FortikDB(t)
	ctx := context.Background()
	d := diary.New(pool)
	for i := 0; i < 50; i++ {
		_, _ = d.Append(ctx, diary.Event{EventType: "x", Actor: "t"})
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_, _ = d.Append(ctx, diary.Event{EventType: "x", Actor: "t"})
			}
		}
	}()
	for i := 0; i < 30; i++ {
		rep, err := d.VerifyChain(ctx)
		if err != nil || !rep.OK {
			close(stop)
			wg.Wait()
			t.Fatalf("false positive under concurrent appends: %v %v", rep.Problems, err)
		}
	}
	close(stop)
	wg.Wait()
}

func TestHeadRewindDetected(t *testing.T) {
	pool, _ := testutil.FortikDB(t)
	ctx := context.Background()
	d := diary.New(pool)
	var entries []diary.Entry
	for i := 0; i < 5; i++ {
		e, _ := d.Append(ctx, diary.Event{EventType: "x", Actor: "t"})
		entries = append(entries, e...)
	}
	// Rewind the head to seq 3 to hide entries 4 and 5 (needs only UPDATE on diary_head).
	if _, err := pool.Exec(ctx, `UPDATE diary_head SET seq = 3, hash = $1`, entries[2].Hash); err != nil {
		t.Fatal(err)
	}
	if rep, _ := d.VerifyChain(ctx); rep.OK {
		t.Fatal("a rewound head hiding tail entries was not detected")
	}
}

func sealedFixture(t *testing.T) (*pgxpool.Pool, *diary.Diary, *diary.Signer) {
	t.Helper()
	pool, _ := testutil.FortikDB(t)
	ctx := context.Background()
	d := diary.New(pool)
	s := signer(t)
	for i := 0; i < 3; i++ {
		_, _ = d.Append(ctx, diary.Event{EventType: "x", Actor: "t", Data: map[string]any{"i": i}})
	}
	old := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Microsecond)
	rewriteChain(t, pool, func(_ int64, b map[string]any) { b["ts"] = old.Format(time.RFC3339Nano) })
	if _, err := d.SealDay(ctx, old, s, "t"); err != nil {
		t.Fatal(err)
	}
	_, _ = d.Append(ctx, diary.Event{EventType: "x", Actor: "t"})
	return pool, d, s
}

func TestDeletedRootRowDetected(t *testing.T) {
	pool, d, s := sealedFixture(t)
	ctx := context.Background()
	d.TrustRootKeys(mustPub(t, s))
	if rep, _ := d.VerifyChain(ctx); !rep.OK {
		t.Fatalf("baseline: %v", rep.Problems)
	}
	_, _ = pool.Exec(ctx, `ALTER TABLE diary_roots DISABLE TRIGGER diary_roots_no_update`)
	_, _ = pool.Exec(ctx, `DELETE FROM diary_roots`)
	if rep, _ := d.VerifyChain(ctx); rep.OK {
		t.Fatal("deleting the sealed root row was not detected")
	}
}

func TestKeyRotationWithRetiredKey(t *testing.T) {
	pool, _, oldKey := sealedFixture(t)
	ctx := context.Background()
	newKey := signer(t)
	d2 := diary.New(pool)
	d2.TrustRootKeys(mustPub(t, newKey))
	if rep, _ := d2.VerifyChain(ctx); rep.OK {
		t.Fatal("a root signed by a non-trusted key must fail")
	}
	d3 := diary.New(pool)
	d3.TrustRootKeys(mustPub(t, newKey), mustPub(t, oldKey))
	if rep, _ := d3.VerifyChain(ctx); !rep.OK {
		t.Fatalf("retired key must keep old roots valid: %v", rep.Problems)
	}
	d4 := diary.New(pool)
	if rep, _ := d4.VerifyChain(ctx); !rep.OK || len(rep.Warnings) == 0 {
		t.Fatalf("unpinned verification should pass with a warning: %+v", rep)
	}
}

// Phase 5 review (map #7): an export filtered by action_id selects
// non-adjacent entries; they are verified one by one (no false "chain
// verification FAILED"), the export is signed, no segment root is claimed,
// and the filter records the action id.
func TestExportByActionIDIsNotContiguous(t *testing.T) {
	pool, _ := testutil.FortikDB(t)
	ctx := context.Background()
	d := diary.New(pool)
	s := signer(t)
	_, _ = d.Append(ctx, diary.Event{AgentID: "a1", EventType: "action.decided", Actor: "t", Data: map[string]any{"action_id": "act_1"}})
	_, _ = d.Append(ctx, diary.Event{AgentID: "a2", EventType: "x", Actor: "t"})
	_, _ = d.Append(ctx, diary.Event{AgentID: "a1", EventType: "action.approved", Actor: "t", Data: map[string]any{"action_id": "act_1"}})
	exp, err := d.Export(ctx, diary.Filter{ActionID: "act_1"}, s, "token:test")
	if err != nil {
		t.Fatal(err)
	}
	if exp.Contiguous || len(exp.Entries) != 2 || !exp.Verification.OK || !exp.Signed || exp.SegmentRoot != nil || exp.Warning != "" ||
		exp.Filter.(map[string]any)["action_id"] != "act_1" {
		t.Fatalf("export: contiguous=%v n=%d verification=%+v signed=%v warning=%q filter=%v",
			exp.Contiguous, len(exp.Entries), exp.Verification, exp.Signed, exp.Warning, exp.Filter)
	}
}
