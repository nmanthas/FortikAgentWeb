package shadow_test

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/action"
	"fortik/internal/alerts"
	"fortik/internal/control"
	"fortik/internal/diary"
	"fortik/internal/shadow"
	"fortik/internal/testutil"
)

var bg = context.Background()

func TestIdentifiers(t *testing.T) {
	tok := "agt_super_secret_value"
	ref := shadow.TokenRef(tok)
	if !regexp.MustCompile(`^[0-9a-f]{12}$`).MatchString(ref) || ref != shadow.TokenRef(tok) || ref == shadow.TokenRef(tok+"x") {
		t.Fatalf("token ref %q", ref)
	}
	if strings.Contains(ref, tok) {
		t.Fatal("token ref contains the token")
	}
	id := shadow.AgentID(shadow.SystemPostgres, shadow.KindDBRole, "up/role")
	if !regexp.MustCompile(`^shadow_postgres_[0-9a-f]{10}$`).MatchString(id) || id != shadow.AgentID(shadow.SystemPostgres, shadow.KindDBRole, "up/role") {
		t.Fatalf("agent id %q", id)
	}
	if err := (&action.Action{AgentID: id, System: "x", Verb: "READ"}).Validate(); err != nil {
		t.Fatalf("agent id is not a valid action agent id: %v", err)
	}
	if g := shadow.AgentID(shadow.SystemGoogle, shadow.KindOAuthGrant, "c"); !strings.HasPrefix(g, "shadow_google_") {
		t.Fatal(g)
	}
	fid := shadow.FindingID("aws", "iam_user_key", "AKIA1")
	if !shadow.ValidFindingID(fid) || shadow.ValidFindingID("shf_xyz") {
		t.Fatalf("finding id %q", fid)
	}
}

func TestSoftwareHintAndClean(t *testing.T) {
	for name, want := range map[string]string{
		"nightly_sync_script": "nightly,sync,script",
		"alice":               "",
		"deploy-bot":          "deploy,bot",
		"ETL.Loader":          "etl,loader",
		"robert":              "",
	} {
		if got := shadow.SoftwareHint(name); got != want {
			t.Errorf("SoftwareHint(%q) = %q, want %q", name, got, want)
		}
	}
	if got := shadow.Clean("a\x00b\nc d  ", 100); got != "abcd" && got != "abc d" {
		t.Fatalf("clean: %q", got)
	}
	if got := shadow.Clean("héllo", 2); got != "h" {
		t.Fatalf("clip on rune boundary: %q", got)
	}
}

// ---- fakes ----

type fakeDiscoverer struct {
	sys string
	mu  sync.Mutex
	res []shadow.ScanResult
	rev shadow.RevokeResult
	got []shadow.Finding
}

func (f *fakeDiscoverer) System() string { return f.sys }
func (f *fakeDiscoverer) Discover(context.Context) []shadow.ScanResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]shadow.ScanResult, len(f.res))
	copy(out, f.res)
	return out
}
func (f *fakeDiscoverer) set(res ...shadow.ScanResult) { f.mu.Lock(); f.res = res; f.mu.Unlock() }
func (f *fakeDiscoverer) Revoke(_ context.Context, fd shadow.Finding) shadow.RevokeResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, fd)
	return f.rev
}

type env struct {
	pool   *pgxpool.Pool
	diary  *diary.Diary
	alerts *alerts.PGStore
	svc    *shadow.Service
	pg     *fakeDiscoverer
}

func newEnv(t *testing.T) *env {
	t.Helper()
	pool, _ := testutil.FortikDB(t)
	d := diary.New(pool)
	al := alerts.NewPGStore(pool, d)
	pg := &fakeDiscoverer{sys: shadow.SystemPostgres}
	svc, err := shadow.NewService(shadow.Config{Pool: pool, Diary: d, Alerts: al, Discoverers: []shadow.Discoverer{pg}})
	if err != nil {
		t.Fatal(err)
	}
	return &env{pool: pool, diary: d, alerts: al, svc: svc, pg: pg}
}

func (e *env) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := e.pool.QueryRow(bg, q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

func (e *env) events(t *testing.T, typ string) int {
	return e.count(t, `SELECT count(*) FROM diary WHERE event_type = $1`, typ)
}

func scriptRole() shadow.Credential {
	return shadow.Credential{Kind: shadow.KindDBRole, Ref: "acme/nightly_sync_script", Holder: "nightly_sync_script", Software: true,
		Integration: "postgres:acme", Label: "postgres role nightly_sync_script on acme",
		Evidence: map[string]any{"role": "nightly_sync_script", "upstream": "acme", "application_names": []string{"python-requests/sync"}}}
}

func personRole() shadow.Credential {
	return shadow.Credential{Kind: shadow.KindDBRole, Ref: "acme/alice", Holder: "alice", Integration: "postgres:acme",
		Evidence: map[string]any{"role": "alice", "application_names": []string{"psql"}}}
}

func TestNewServiceValidation(t *testing.T) {
	if _, err := shadow.NewService(shadow.Config{}); err == nil {
		t.Fatal("empty config accepted")
	}
}

func TestScanFlagsSoftwareAndIsIdempotent(t *testing.T) {
	e := newEnv(t)
	e.pg.set(shadow.ScanResult{System: shadow.SystemPostgres, Integration: "postgres:acme", Status: shadow.ScanScanned,
		Credentials: []shadow.Credential{scriptRole(), personRole()}})
	rep, err := e.svc.Scan(bg, "user:sec@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Found != 2 || rep.Software != 1 || rep.New != 2 || rep.Flagged != 1 {
		t.Fatalf("report: %+v", rep)
	}
	// Systems without a discoverer are reported as not scanned, never as empty.
	ns := strings.Join(rep.NotScanned, ",")
	for _, s := range []string{"github", "aws", "google_workspace"} {
		if !strings.Contains(ns, s) {
			t.Fatalf("%s missing from not_scanned %v", s, rep.NotScanned)
		}
	}
	list, err := e.svc.List(bg, shadow.Filter{Status: shadow.StatusFlagged})
	if err != nil || len(list) != 1 {
		t.Fatalf("flagged list: %v %+v", err, list)
	}
	f := list[0]
	wantAgent := shadow.AgentID(shadow.SystemPostgres, shadow.KindDBRole, "acme/nightly_sync_script")
	if f.AgentID != wantAgent || !f.UsedBySoftware || f.CredentialRef != "acme/nightly_sync_script" {
		t.Fatalf("finding: %+v", f)
	}
	st, err := control.Get(bg, e.pool, wantAgent)
	if err != nil || !st.Registered || !st.Discovered || st.Sponsor != "" || st.Level != control.Isolated {
		t.Fatalf("discovered agent: %+v %v", st, err)
	}
	if n := e.count(t, `SELECT copy_cap FROM agents WHERE agent_id = $1`, wantAgent); n != 0 {
		t.Fatalf("copy_cap %d", n)
	}
	person, _ := e.svc.List(bg, shadow.Filter{Status: shadow.StatusOpen})
	if len(person) != 1 || person[0].AgentID != "" || person[0].UsedBySoftware {
		t.Fatalf("person finding: %+v", person)
	}
	if e.events(t, shadow.EventAgentFound) != 1 || e.events(t, shadow.EventFound) != 2 || e.events(t, shadow.EventScanned) != 1 {
		t.Fatalf("diary: discovered=%d found=%d scanned=%d", e.events(t, shadow.EventAgentFound), e.events(t, shadow.EventFound), e.events(t, shadow.EventScanned))
	}
	al, err := e.alerts.List(bg, alerts.Filter{Kind: shadow.AlertKindShadow})
	if err != nil || len(al) != 1 || al[0].AgentID != wantAgent {
		t.Fatalf("alerts: %v %+v", err, al)
	}

	// Second scan: nothing new, no duplicate agent, event or alert.
	rep, err = e.svc.Scan(bg, "", "")
	if err != nil || rep.New != 0 || rep.Flagged != 0 || rep.Found != 2 {
		t.Fatalf("rescan: %v %+v", err, rep)
	}
	if e.events(t, shadow.EventAgentFound) != 1 || e.events(t, shadow.EventFound) != 2 ||
		e.count(t, `SELECT count(*) FROM agents WHERE discovered`) != 1 || e.count(t, `SELECT count(*) FROM shadow_findings`) != 2 {
		t.Fatal("rescan was not idempotent")
	}
	if al, _ := e.alerts.List(bg, alerts.Filter{Kind: shadow.AlertKindShadow}); len(al) != 1 {
		t.Fatalf("alerts after rescan: %+v", al)
	}
	if e.svc.LastScan() == nil {
		t.Fatal("last scan not kept")
	}
}

func TestRevokeDismissRegister(t *testing.T) {
	e := newEnv(t)
	e.pg.set(shadow.ScanResult{System: shadow.SystemPostgres, Status: shadow.ScanScanned,
		Credentials: []shadow.Credential{scriptRole(), personRole()}})
	if _, err := e.svc.Scan(bg, "", ""); err != nil {
		t.Fatal(err)
	}
	script := shadow.FindingID(shadow.SystemPostgres, shadow.KindDBRole, "acme/nightly_sync_script")
	person := shadow.FindingID(shadow.SystemPostgres, shadow.KindDBRole, "acme/alice")

	if _, _, err := e.svc.Revoke(bg, script, "user:sec", "bad\x01reason"); !errors.Is(err, shadow.ErrInvalid) {
		t.Fatalf("revoke with a control character in the reason: %v", err)
	}
	if _, _, err := e.svc.Revoke(bg, "shf_0000000000000000", "user:sec", "r"); !errors.Is(err, shadow.ErrNotFound) {
		t.Fatalf("revoke unknown: %v", err)
	}
	// A failed revoke is recorded honestly and leaves the status alone.
	e.pg.rev = shadow.RevokeResult{Outcome: shadow.OutcomeNotRevoked, Detail: "permission denied"}
	f, res, err := e.svc.Revoke(bg, script, "user:sec", "script with a standing password")
	if err != nil || res.Outcome != shadow.OutcomeNotRevoked || f.Status != shadow.StatusFlagged {
		t.Fatalf("failed revoke: %v %+v %+v", err, res, f)
	}
	if e.events(t, shadow.EventRevokeFailed) != 1 {
		t.Fatal("revoke failure not in the diary")
	}
	// A revoker returning nonsense counts as not revoked.
	e.pg.rev = shadow.RevokeResult{}
	if _, res, _ := e.svc.Revoke(bg, script, "user:sec", "again"); res.Outcome != shadow.OutcomeNotRevoked {
		t.Fatalf("empty outcome: %+v", res)
	}
	e.pg.rev = shadow.RevokeResult{Outcome: shadow.OutcomeRevoked, Detail: "NOLOGIN"}
	f, res, err = e.svc.Revoke(bg, script, "user:sec", "script with a standing password")
	if err != nil || res.Outcome != shadow.OutcomeRevoked || f.Status != shadow.StatusRevoked || f.UpdatedBy != "user:sec" {
		t.Fatalf("revoke: %v %+v %+v", err, res, f)
	}
	if _, _, err := e.svc.Revoke(bg, script, "user:sec", "x"); !errors.Is(err, shadow.ErrState) {
		t.Fatalf("second revoke: %v", err)
	}
	// The credential comes back (LOGIN re-enabled): reopened and flagged again.
	rep, err := e.svc.Scan(bg, "", "")
	if err != nil || rep.Flagged != 1 {
		t.Fatalf("reactivation: %v %+v", err, rep)
	}
	if f, _ := e.svc.Get(bg, script); f.Status != shadow.StatusFlagged {
		t.Fatalf("reactivated finding: %+v", f)
	}

	// Dismiss needs a reason and an open/flagged finding.
	if _, err := e.svc.Dismiss(bg, person, "user:sec", "x\x00"); !errors.Is(err, shadow.ErrInvalid) {
		t.Fatalf("dismiss with a NUL in the reason: %v", err)
	}
	f, err = e.svc.Dismiss(bg, person, "user:sec", "")
	if err != nil || f.Status != shadow.StatusDismissed {
		t.Fatalf("dismiss: %v %+v", err, f)
	}
	if _, err := e.svc.Dismiss(bg, person, "user:sec", "again"); !errors.Is(err, shadow.ErrState) {
		t.Fatalf("dismiss twice: %v", err)
	}
	// A dismissed finding stays dismissed across scans.
	if _, err := e.svc.Scan(bg, "", ""); err != nil {
		t.Fatal(err)
	}
	if f, _ := e.svc.Get(bg, person); f.Status != shadow.StatusDismissed {
		t.Fatalf("dismissed finding reopened: %+v", f)
	}

	// Register validates and keeps the level.
	for _, in := range []shadow.RegisterInput{
		{Sponsor: "", Name: "x"}, {Sponsor: "not-an-email", Name: "x"}, {Sponsor: "a@b.co", Name: ""}, {Sponsor: "a@b.co", Name: "x\x00y"},
	} {
		if _, err := e.svc.Register(bg, script, "user:sec", in); !errors.Is(err, shadow.ErrInvalid) {
			t.Fatalf("register %+v: %v", in, err)
		}
	}
	f, err = e.svc.Register(bg, script, "user:sec", shadow.RegisterInput{Sponsor: "Owner@Example.com", Name: "Nightly sync", Team: "data"})
	if err != nil || f.Status != shadow.StatusRegistered {
		t.Fatalf("register: %v %+v", err, f)
	}
	st, _ := control.Get(bg, e.pool, f.AgentID)
	if st.Sponsor != "owner@example.com" || st.Team != "data" || st.Level != control.Isolated || !st.Discovered {
		t.Fatalf("registered agent: %+v", st)
	}
	if _, err := e.svc.Register(bg, script, "user:sec", shadow.RegisterInput{Sponsor: "a@b.co", Name: "x"}); !errors.Is(err, shadow.ErrState) {
		t.Fatalf("register twice: %v", err)
	}
	// Registering a finding without an agent creates one (ISOLATED, owned).
	f, err = e.svc.Register(bg, person, "user:sec", shadow.RegisterInput{Sponsor: "alice@example.com", Name: "Alice's notebook"})
	if err != nil || f.AgentID == "" {
		t.Fatalf("register person finding: %v %+v", err, f)
	}
	if st, _ := control.Get(bg, e.pool, f.AgentID); st.Level != control.Isolated || st.Sponsor != "alice@example.com" {
		t.Fatalf("agent: %+v", st)
	}
	if e.events(t, shadow.EventRegistered) != 2 || e.events(t, shadow.EventDismissed) != 1 || e.events(t, shadow.EventRevoked) != 1 {
		t.Fatal("diary events missing")
	}
}

func TestNeverHijacksARegisteredAgent(t *testing.T) {
	e := newEnv(t)
	id := shadow.AgentID(shadow.SystemPostgres, shadow.KindDBRole, "acme/nightly_sync_script")
	if _, err := e.pool.Exec(bg, `INSERT INTO agents (agent_id, name, sponsor) VALUES ($1, 'real', 'x@y.z')`, id); err != nil {
		t.Fatal(err)
	}
	e.pg.set(shadow.ScanResult{System: shadow.SystemPostgres, Status: shadow.ScanScanned, Credentials: []shadow.Credential{scriptRole()}})
	rep, err := e.svc.Scan(bg, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Systems[0].Status != shadow.ScanPartial || rep.Systems[0].Failed != 1 || rep.Flagged != 0 {
		t.Fatalf("report: %+v", rep.Systems[0])
	}
	st, _ := control.Get(bg, e.pool, id)
	if st.Discovered || st.Sponsor != "x@y.z" {
		t.Fatalf("registered agent changed: %+v", st)
	}
}

func TestScanReportsErrorsHonestly(t *testing.T) {
	e := newEnv(t)
	e.pg.set(shadow.ScanResult{System: shadow.SystemPostgres, Integration: "postgres:acme", Status: shadow.ScanError, Detail: "connection failed: not scanned"})
	rep, err := e.svc.Scan(bg, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(rep.NotScanned, ","), "postgres:acme") {
		t.Fatalf("error not reported as not scanned: %+v", rep)
	}
	// A discoverer that returns nothing is an error, not "nothing found".
	e.pg.set()
	rep, _ = e.svc.Scan(bg, "", "")
	if rep.Systems[0].Status != shadow.ScanError {
		t.Fatalf("empty result: %+v", rep.Systems[0])
	}
}

func TestEnricher(t *testing.T) {
	e := newEnv(t)
	en := shadow.NewEnricher(e.pool)
	if en.Key() != "shadow" {
		t.Fatal(en.Key())
	}
	if v, err := en.Enrich(bg, action.Action{}, control.State{AgentID: "x"}); v != nil || err != nil {
		t.Fatalf("non-discovered: %v %v", v, err)
	}
	e.pg.set(shadow.ScanResult{System: shadow.SystemPostgres, Status: shadow.ScanScanned, Credentials: []shadow.Credential{scriptRole()}})
	if _, err := e.svc.Scan(bg, "", ""); err != nil {
		t.Fatal(err)
	}
	id := shadow.AgentID(shadow.SystemPostgres, shadow.KindDBRole, "acme/nightly_sync_script")
	v, err := en.Enrich(bg, action.Action{}, control.State{AgentID: id, Discovered: true})
	if err != nil || v.(map[string]any)["flagged"] != true {
		t.Fatalf("flagged: %v %v", v, err)
	}
	fid := shadow.FindingID(shadow.SystemPostgres, shadow.KindDBRole, "acme/nightly_sync_script")
	if _, err := e.svc.Register(bg, fid, "user:sec", shadow.RegisterInput{Sponsor: "o@example.com", Name: "n"}); err != nil {
		t.Fatal(err)
	}
	v, _ = en.Enrich(bg, action.Action{}, control.State{AgentID: id, Discovered: true})
	if v.(map[string]any)["flagged"] != false {
		t.Fatalf("after register: %v", v)
	}
}
