package access_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/access"
	"fortik/internal/control"
	"fortik/internal/diary"
	"fortik/internal/testutil"
)

type fixture struct {
	pool  *pgxpool.Pool
	d     *diary.Diary
	ctl   *control.Store
	store *access.PGStore
}

func setup(t *testing.T) fixture {
	t.Helper()
	pool, _ := testutil.FortikDB(t)
	d := diary.New(pool)
	ctl := control.NewStore(pool, d)
	for _, a := range []control.Agent{
		{AgentID: "claude_code_01", Type: "coding", Sponsor: "Jane@Acme.com"},
		{AgentID: "finance_agent_07", Type: "finance", Sponsor: "bob@acme.com"},
	} {
		if _, err := ctl.Register(context.Background(), a, "test"); err != nil {
			t.Fatal(err)
		}
	}
	return fixture{pool: pool, d: d, ctl: ctl, store: access.NewPGStore(pool, d)}
}

func count(t *testing.T, f fixture, q string, args ...any) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// lastChange returns the data of the newest access.changed Diary event.
func lastChange(t *testing.T, f fixture) (string, map[string]any) {
	t.Helper()
	var actor, body string
	if err := f.pool.QueryRow(context.Background(), `SELECT actor, body_json FROM diary WHERE event_type = 'access.changed' ORDER BY seq DESC LIMIT 1`).
		Scan(&actor, &body); err != nil {
		t.Fatal(err)
	}
	var b struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &b); err != nil {
		t.Fatal(err)
	}
	return actor, b.Data
}

func TestPutCurrentHistoryAndDiary(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if _, err := f.store.Current(ctx, "claude_code_01", "postgres"); !errors.Is(err, access.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	p1, err := f.store.Put(ctx, "claude_code_01", "postgres", json.RawMessage(`{"upstreams":{"acme_prod":"read_only"}}`), "user:sec@acme.com", "initial grant")
	if err != nil {
		t.Fatal(err)
	}
	if p1.Version != 1 || p1.ChangedBy != "user:sec@acme.com" || p1.Reason != "initial grant" || p1.ChangedAt.IsZero() {
		t.Fatalf("got %+v", p1)
	}
	actor, data := lastChange(t, f)
	if actor != "user:sec@acme.com" || data["system"] != "postgres" || data["from_version"] != float64(0) || data["to_version"] != float64(1) ||
		data["old"] != nil || data["reason"] != "initial grant" {
		t.Fatalf("diary: actor=%s data=%v", actor, data)
	}
	if fmt.Sprint(data["new"]) != "map[upstreams:map[acme_prod:read_only]]" {
		t.Fatalf("diary new: %v", data["new"])
	}

	p2, err := f.store.Put(ctx, "claude_code_01", "postgres", json.RawMessage(`{"upstreams":{"acme_prod":"read_write"}}`), "user:sec@acme.com", "migration week")
	if err != nil {
		t.Fatal(err)
	}
	if p2.Version != 2 {
		t.Fatalf("version %d", p2.Version)
	}
	_, data = lastChange(t, f)
	if data["from_version"] != float64(1) || data["to_version"] != float64(2) || fmt.Sprint(data["old"]) != "map[upstreams:map[acme_prod:read_only]]" {
		t.Fatalf("diary: %v", data)
	}
	cur, err := f.store.Current(ctx, "claude_code_01", "postgres")
	if err != nil || cur.Version != 2 || !strings.Contains(string(cur.Profile), "read_write") {
		t.Fatalf("current %+v %v", cur, err)
	}
	hist, err := f.store.History(ctx, "claude_code_01", "postgres", 0)
	if err != nil || len(hist) != 2 || hist[0].Version != 2 || hist[1].Version != 1 {
		t.Fatalf("history %+v %v", hist, err)
	}
	if hist, _ := f.store.History(ctx, "claude_code_01", "postgres", 1); len(hist) != 1 {
		t.Fatalf("limit ignored: %d", len(hist))
	}
	// Other agents and systems are independent.
	if _, err := f.store.Put(ctx, "claude_code_01", "aws", json.RawMessage(`{"mode":"read_only","services":["s3"]}`), "user:sec@acme.com", "s3 reads"); err != nil {
		t.Fatal(err)
	}
	all, err := f.store.All(ctx, "claude_code_01")
	if err != nil || len(all) != 2 || all[0].System != "aws" || all[1].System != "postgres" || all[1].Version != 2 {
		t.Fatalf("all %+v %v", all, err)
	}
	if all, _ := f.store.All(ctx, "finance_agent_07"); len(all) != 0 {
		t.Fatalf("other agent has profiles: %+v", all)
	}
	if n := count(t, f, `SELECT access_profile_version FROM agents WHERE agent_id = 'claude_code_01'`); n != 3 {
		t.Fatalf("access_profile_version %d", n)
	}
}

func TestPutRejectsWithoutWriting(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	before := count(t, f, `SELECT count(*) FROM diary`)
	cases := []struct {
		agent, system, profile, actor, reason string
		want                                  error
	}{
		{"claude_code_01", "postgres", `{"upstreams":{"x":"admin"}}`, "u", "r", access.ErrInvalidProfile},
		{"claude_code_01", "postgres", `{"upstreams":{}, "extra": 1}`, "u", "r", access.ErrInvalidProfile},
		{"claude_code_01", "shell", `{}`, "u", "r", access.ErrInvalidProfile},
		{"claude_code_01", "postgres", `{"upstreams":{}}`, "u", "  ", access.ErrInvalidProfile},
		{"claude_code_01", "postgres", `{"upstreams":{}}`, "u", strings.Repeat("x", 1001), access.ErrInvalidProfile},
		{"ghost_agent", "postgres", `{"upstreams":{}}`, "u", "r", access.ErrAgentNotFound},
	}
	for i, c := range cases {
		if _, err := f.store.Put(ctx, c.agent, c.system, json.RawMessage(c.profile), c.actor, c.reason); !errors.Is(err, c.want) {
			t.Errorf("case %d: want %v, got %v", i, c.want, err)
		}
	}
	if _, err := f.store.Put(ctx, "claude_code_01", "postgres", json.RawMessage(`{"upstreams":{}}`), "", "r"); err == nil {
		t.Error("empty actor accepted")
	}
	if n := count(t, f, `SELECT count(*) FROM access_profiles`); n != 0 {
		t.Fatalf("%d rows written", n)
	}
	if after := count(t, f, `SELECT count(*) FROM diary`); after != before {
		t.Fatalf("diary grew by %d", after-before)
	}
}

func TestVersionsAreAppendOnly(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if _, err := f.store.Put(ctx, "claude_code_01", "drive", json.RawMessage(`{"mode":"read_only","share":"none"}`), "u", "r"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE access_profiles SET profile_json = '{}'`); err == nil {
		t.Fatal("update allowed")
	}
	if _, err := f.pool.Exec(ctx, `DELETE FROM access_profiles`); err == nil {
		t.Fatal("delete allowed")
	}
}

func TestRevertCopiesVersion(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	for _, p := range []string{`{"mode":"read_only","share":"none"}`, `{"mode":"read_write","share":"any"}`} {
		if _, err := f.store.Put(ctx, "claude_code_01", "drive", json.RawMessage(p), "user:sec@acme.com", "change"); err != nil {
			t.Fatal(err)
		}
	}
	p, err := f.store.Revert(ctx, "claude_code_01", "drive", 1, "user:sec@acme.com", "too broad")
	if err != nil {
		t.Fatal(err)
	}
	if p.Version != 3 || string(p.Profile) != `{"mode": "read_only", "share": "none"}` {
		t.Fatalf("got v%d %s", p.Version, p.Profile)
	}
	_, data := lastChange(t, f)
	if data["reverted_from"] != float64(1) || data["from_version"] != float64(2) || data["to_version"] != float64(3) {
		t.Fatalf("diary %v", data)
	}
	if _, err := f.store.Revert(ctx, "claude_code_01", "drive", 9, "u", "r"); !errors.Is(err, access.ErrNotFound) {
		t.Fatalf("missing version: %v", err)
	}
	if _, err := f.store.Revert(ctx, "claude_code_01", "drive", 0, "u", "r"); !errors.Is(err, access.ErrInvalidProfile) {
		t.Fatalf("version 0: %v", err)
	}
	if _, err := f.store.Revert(ctx, "claude_code_01", "gmail", 1, "u", "r"); !errors.Is(err, access.ErrNotFound) {
		t.Fatalf("no history: %v", err)
	}
}

func TestGuardRunsAgainstLockedCurrent(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if _, err := f.store.Put(ctx, "claude_code_01", "aws", json.RawMessage(`{"mode":"read_only","services":["s3"]}`), "u", "r"); err != nil {
		t.Fatal(err)
	}
	refuse := errors.New("refused by guard")
	var sawPrev, sawNext string
	_, err := f.store.PutGuarded(ctx, "claude_code_01", "aws", json.RawMessage(`{"mode":"read_write","services":["s3"]}`), "u", "r",
		func(prev, next json.RawMessage) error {
			sawPrev, sawNext = string(prev), string(next)
			return refuse
		})
	if !errors.Is(err, refuse) {
		t.Fatalf("got %v", err)
	}
	if !strings.Contains(sawPrev, `"read_only"`) || sawNext != `{"mode":"read_write","services":["s3"],"denied_actions":[]}` {
		t.Fatalf("guard saw prev=%s next=%s", sawPrev, sawNext)
	}
	if n := count(t, f, `SELECT count(*) FROM access_profiles`); n != 1 {
		t.Fatalf("guarded write landed: %d rows", n)
	}
}

func TestConcurrentPutsGetDistinctVersions(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := f.store.Put(ctx, "claude_code_01", "gmail",
				json.RawMessage(fmt.Sprintf(`{"send":"any","read":true,"max_recipients":%d}`, i)), "u", "r")
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := count(t, f, `SELECT count(DISTINCT version) FROM access_profiles WHERE system = 'gmail'`); n != 10 {
		t.Fatalf("%d distinct versions", n)
	}
	if n := count(t, f, `SELECT max(version) FROM access_profiles WHERE system = 'gmail'`); n != 10 {
		t.Fatalf("max version %d", n)
	}
	if res, err := f.d.VerifyChain(ctx); err != nil || !res.OK {
		t.Fatalf("diary chain: %+v %v", res, err)
	}
}

func TestPolicyInput(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	pi, err := f.store.PolicyInput(ctx, "claude_code_01", "postgres")
	if err != nil || pi.System != "postgres" || pi.Version != 0 || string(pi.Profile) != "null" {
		t.Fatalf("no profile: %+v %v", pi, err)
	}
	pi, err = f.store.PolicyInput(ctx, "claude_code_01", "mcp")
	if err != nil || pi.System != "mcp" || pi.Version != 0 || string(pi.Profile) != "null" {
		t.Fatalf("unprofiled system: %+v %v", pi, err)
	}
	if _, err := f.store.Put(ctx, "claude_code_01", "postgres", json.RawMessage(`{"upstreams":{"acme_prod":"read_only"}}`), "u", "r"); err != nil {
		t.Fatal(err)
	}
	pi, err = f.store.PolicyInput(ctx, "claude_code_01", "postgres")
	if err != nil || pi.Version != 1 || !strings.Contains(string(pi.Profile), "acme_prod") {
		t.Fatalf("with profile: %+v %v", pi, err)
	}
	b, _ := json.Marshal(pi)
	if !strings.Contains(string(b), `"profile":{"upstreams"`) {
		t.Fatalf("encoded %s", b)
	}
	// A store failure is an error (Decide fails closed), never "no profile".
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := f.store.PolicyInput(cctx, "claude_code_01", "postgres"); err == nil {
		t.Fatal("cancelled context returned no error")
	}
}
