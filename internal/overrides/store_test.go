package overrides

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"fortik/internal/access"
	"fortik/internal/action"
	"fortik/internal/alerts"
	"fortik/internal/broker"
	"fortik/internal/control"
	"fortik/internal/decide"
)

// The production dependencies satisfy the interfaces the lead wires in.
var (
	_ decide.Enricher = (*Enricher)(nil)
	_ Revoker         = broker.Adapter(nil)
	_ ProfileReverter = (*access.PGStore)(nil)
	_ AlertRaiser     = (*alerts.PGStore)(nil)
)

func TestCreateValidation(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	base := agentReq("code_agent_12", "github", ModeSuspended, 30*time.Minute)
	cases := map[string]func(r *CreateRequest){
		"bad scope":         func(r *CreateRequest) { r.Scope = "org" },
		"bad agent id":      func(r *CreateRequest) { r.ScopeID = "bad id!" },
		"bad team":          func(r *CreateRequest) { r.Scope, r.ScopeID = ScopeTeam, " platform" },
		"unknown system":    func(r *CreateRequest) { r.System = "slack" },
		"bad mode":          func(r *CreateRequest) { r.Mode = "frozen" },
		"no reason":         func(r *CreateRequest) { r.Reason = "  " },
		"reason too long":   func(r *CreateRequest) { r.Reason = strings.Repeat("x", 1001) },
		"too short":         func(r *CreateRequest) { r.Duration = 59 * time.Second },
		"too long":          func(r *CreateRequest) { r.Duration = 30*24*time.Hour + time.Second },
		"no duration":       func(r *CreateRequest) { r.Duration = 0 },
		"duration and open": func(r *CreateRequest) { r.UntilReleased = true },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			r := base
			mut(&r)
			if _, err := f.store.Create(ctx, r, secActor, nil); !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
		})
	}
	if _, err := f.store.Create(ctx, agentReq("ghost_agent", "github", ModeSuspended, time.Hour), secActor, nil); !errors.Is(err, ErrScopeNotFound) {
		t.Fatalf("unknown agent: %v", err)
	}
	team := CreateRequest{Scope: ScopeTeam, ScopeID: "nobody", System: "github", Mode: ModeSuspended, UntilReleased: true, Reason: "r"}
	if _, err := f.store.Create(ctx, team, secActor, nil); !errors.Is(err, ErrScopeNotFound) {
		t.Fatalf("empty team: %v", err)
	}
	if n := f.count(t, `SELECT count(*) FROM access_overrides`); n != 0 {
		t.Fatalf("%d overrides stored by refused requests", n)
	}
	for _, r := range f.revokers {
		if len(r.Calls()) != 0 {
			t.Fatalf("revoker %s called by a refused request", r.system)
		}
	}
	// Bounds are inclusive.
	for _, d := range []time.Duration{MinDuration, MaxDuration} {
		if _, err := f.store.Create(ctx, agentReq("code_agent_12", "github", ModeSuspended, d), secActor, nil); err != nil {
			t.Fatalf("duration %s: %v", d, err)
		}
	}
}

// On create only THAT system's credentials are revoked; the result is stored
// with the override; issuances on that system are marked revoked; and the
// change and the revocation each have their Diary events.
func TestCreateRevokesOnlyThatSystem(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	for _, sys := range []string{"github", "drive"} {
		if _, err := f.pool.Exec(ctx, `INSERT INTO credential_issuances (issuance_id, agent_id, system, expires_at)
			VALUES ($1, 'code_agent_12', $2, now() + interval '10 minutes')`, action.NewID("iss"), sys); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.profiles.Put(ctx, "code_agent_12", "github", json.RawMessage(`{"repos":["acme/api"],"permissions":{"contents":"write"}}`), secActor, "seed"); err != nil {
		t.Fatal(err)
	}
	o := mustCreate(t, f, agentReq("code_agent_12", "github", ModeSuspended, 30*time.Minute))
	if o.Status != StatusActive || o.ExpiresAt == nil || o.CreatedBy != secActor || o.RestoreProfileVersion != 1 {
		t.Fatalf("override: %+v", o)
	}
	if d := o.ExpiresAt.Sub(o.StartsAt); d < 29*time.Minute || d > 31*time.Minute {
		t.Fatalf("expiry %s after start", d)
	}
	if got := f.revokers["github"].Calls(); !slices.Equal(got, []string{"code_agent_12"}) {
		t.Fatalf("github revoker calls: %v", got)
	}
	for _, sys := range []string{"gmail", "drive", "aws", "postgres"} {
		if c := f.revokers[sys].Calls(); len(c) != 0 {
			t.Fatalf("%s revoker called: %v", sys, c)
		}
	}
	want := `{"github":{"code_agent_12":"github tokens revoked for code_agent_12"}}`
	if string(o.RevokeResult) != want {
		t.Fatalf("revoke_result %s", o.RevokeResult)
	}
	stored, err := f.store.Get(ctx, o.OverrideID)
	if err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(stored.RevokeResult, []byte(want)) {
		t.Fatalf("stored revoke_result %s", stored.RevokeResult)
	}
	if n := f.count(t, `SELECT count(*) FROM credential_issuances WHERE system = 'github' AND revoked_at IS NOT NULL`); n != 1 {
		t.Fatalf("github issuances marked: %d", n)
	}
	if n := f.count(t, `SELECT count(*) FROM credential_issuances WHERE system = 'drive' AND revoked_at IS NULL`); n != 1 {
		t.Fatal("drive issuance touched")
	}
	created := f.events(t, EventCreated)
	if len(created) != 1 || created[0]["override_id"] != o.OverrideID || created[0]["system"] != "github" || created[0]["until_released"] != false {
		t.Fatalf("override.created: %v", created)
	}
	rev := f.events(t, EventCredentialRevoked)
	if len(rev) != 1 || rev[0]["system"] != "github" || rev[0]["succeeded"] != true || rev[0]["override_id"] != o.OverrideID {
		t.Fatalf("credential.revoked: %v", rev)
	}
	f.verifyDiary(t)
}

func TestCreateReportsRevocationFailureAndMissingRevoker(t *testing.T) {
	f := setup(t)
	f.revokers["aws"].err = errors.New("iam unreachable\nretry later")
	o := mustCreate(t, f, agentReq("code_agent_12", "aws", ModeSuspended, time.Hour))
	var res map[string]map[string]string
	if err := json.Unmarshal(o.RevokeResult, &res); err != nil {
		t.Fatal(err)
	}
	if got := res["aws"]["code_agent_12"]; got != "revocation FAILED: iam unreachable retry later" {
		t.Fatalf("aws result %q", got)
	}
	if o.Status != StatusActive {
		t.Fatal("override must stay in force when revocation fails")
	}
	ev := f.events(t, EventCredentialRevoked)
	if len(ev) != 1 || ev[0]["succeeded"] != false {
		t.Fatalf("events %v", ev)
	}
	// A system with no credential revoker says so honestly.
	o = mustCreate(t, f, agentReq("code_agent_12", "shell", ModeSuspended, time.Hour))
	if !strings.Contains(string(o.RevokeResult), "no credential revoker for shell") {
		t.Fatalf("shell result %s", o.RevokeResult)
	}
}

func TestTeamScope(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	o := mustCreate(t, f, CreateRequest{Scope: ScopeTeam, ScopeID: "platform", System: "github", Mode: ModeReadOnly, UntilReleased: true, Reason: "freeze"})
	if o.ExpiresAt != nil || o.RestoreProfileVersion != 0 {
		t.Fatalf("team override %+v", o)
	}
	if got := f.revokers["github"].Calls(); !slices.Equal(got, []string{"code_agent_12", "code_agent_13", "code_agent_14"}) {
		t.Fatalf("team revocations %v", got)
	}
	e := NewEnricher(f.store)
	for agent, want := range map[string]int{"code_agent_12": 1, "code_agent_13": 1, "finance_agent_07": 0} {
		st, err := f.ctl.Get(ctx, agent)
		if err != nil {
			t.Fatal(err)
		}
		v, err := e.Enrich(ctx, action.Action{AgentID: agent, System: "github", Verb: action.VerbRead}, st)
		if err != nil {
			t.Fatal(err)
		}
		if pc := v.(PolicyContext); len(pc.Active) != want {
			t.Fatalf("%s: %d overrides in force, want %d", agent, len(pc.Active), want)
		}
	}
	// Other systems are unaffected.
	st, _ := f.ctl.Get(ctx, "code_agent_12")
	v, _ := e.Enrich(ctx, action.Action{AgentID: "code_agent_12", System: "drive", Verb: action.VerbRead}, st)
	if pc := v.(PolicyContext); len(pc.Active) != 0 {
		t.Fatalf("drive: %+v", pc)
	}
	// An unregistered agent never inherits a team (it has none).
	v, _ = e.Enrich(ctx, action.Action{AgentID: "ghost", System: "github"}, control.State{AgentID: "ghost", Team: "platform"})
	if pc := v.(PolicyContext); len(pc.Active) != 0 {
		t.Fatalf("unregistered: %+v", pc)
	}
	list, err := f.store.List(ctx, ListFilter{AgentID: "code_agent_13"})
	if err != nil || len(list) != 1 || list[0].OverrideID != o.OverrideID {
		t.Fatalf("list by member: %v %v", list, err)
	}
	if ev := f.events(t, EventCredentialRevoked); len(ev) != 3 {
		t.Fatalf("%d credential.revoked events", len(ev))
	}
}

func TestEnricherMostRestrictiveFirstAndFailsClosed(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	ro := mustCreate(t, f, CreateRequest{Scope: ScopeTeam, ScopeID: "platform", System: "github", Mode: ModeReadOnly, UntilReleased: true, Reason: "freeze"})
	short := mustCreate(t, f, agentReq("code_agent_12", "github", ModeSuspended, time.Hour))
	long := mustCreate(t, f, agentReq("code_agent_12", "github", ModeSuspended, 2*time.Hour))
	e := NewEnricher(f.store)
	st, _ := f.ctl.Get(ctx, "code_agent_12")
	v, err := e.Enrich(ctx, action.Action{AgentID: "code_agent_12", System: "github"}, st)
	if err != nil {
		t.Fatal(err)
	}
	got := v.(PolicyContext).Active
	ids := []string{}
	for _, o := range got {
		ids = append(ids, o.OverrideID)
	}
	if !slices.Equal(ids, []string{long.OverrideID, short.OverrideID, ro.OverrideID}) {
		t.Fatalf("order %v", ids)
	}
	if w, _ := MostRestrictive(got); w.OverrideID != long.OverrideID {
		t.Fatal("most restrictive")
	}
	if e.Key() != "overrides" {
		t.Fatal("key")
	}
	if _, err := f.pool.Exec(ctx, `ALTER TABLE access_overrides RENAME TO access_overrides_gone`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Enrich(ctx, action.Action{AgentID: "code_agent_12", System: "github"}, st); err == nil {
		t.Fatal("enricher must error (fail closed) when the store is unavailable")
	}
}

func TestSortMostRestrictive(t *testing.T) {
	at := func(m int) *time.Time { v := time.Date(2026, 10, 11, 11, m, 0, 0, time.UTC); return &v }
	list := []Override{
		{OverrideID: "a", Mode: ModeReadOnly, Status: StatusActive},
		{OverrideID: "b", Mode: ModeSuspended, Status: StatusActive, ExpiresAt: at(30)},
		{OverrideID: "c", Mode: ModeSuspended, Status: StatusActive, ExpiresAt: at(55)},
		{OverrideID: "d", Mode: ModeSuspended, Status: StatusBlocked, ExpiresAt: at(10)},
		{OverrideID: "e", Mode: "bogus", Status: StatusActive, ExpiresAt: at(1)},
	}
	SortMostRestrictive(list)
	var ids string
	for _, o := range list {
		ids += o.OverrideID
	}
	if ids != "dcbea" {
		t.Fatalf("order %s", ids)
	}
	if _, ok := MostRestrictive(nil); ok {
		t.Fatal("empty")
	}
}

func TestReleaseExtendPermanent(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	o := mustCreate(t, f, agentReq("code_agent_12", "github", ModeSuspended, time.Hour))

	ext, err := f.store.Extend(ctx, o.OverrideID, 30*time.Minute, secActor, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if d := ext.ExpiresAt.Sub(*o.ExpiresAt); d < 29*time.Minute || d > 31*time.Minute {
		t.Fatalf("extended by %s", d)
	}
	if _, err := f.store.Extend(ctx, o.OverrideID, 30*24*time.Hour, secActor, "", nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("extend past max: %v", err)
	}
	if _, err := f.store.Extend(ctx, o.OverrideID, time.Second, secActor, "", nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("extend below min: %v", err)
	}
	perm, err := f.store.MakePermanent(ctx, o.OverrideID, secActor, "investigation", nil)
	if err != nil || perm.ExpiresAt != nil || perm.Status != StatusActive {
		t.Fatalf("permanent: %+v %v", perm, err)
	}
	if _, err := f.store.MakePermanent(ctx, o.OverrideID, secActor, "", nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("permanent twice: %v", err)
	}
	if _, err := f.store.Extend(ctx, o.OverrideID, time.Hour, secActor, "", nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("extend until-released: %v", err)
	}
	denied := errors.New("denied by authorizer")
	if _, err := f.store.Release(ctx, o.OverrideID, "user:x@acme.com", "", func(context.Context, pgx.Tx, Override) error { return denied }); !errors.Is(err, denied) {
		t.Fatalf("authorizer not applied: %v", err)
	}
	rel, err := f.store.Release(ctx, o.OverrideID, secActor, "fixed", nil)
	if err != nil || rel.Status != StatusReleased || rel.RestoredAt == nil {
		t.Fatalf("release: %+v %v", rel, err)
	}
	for name, fn := range map[string]func() error{
		"release":   func() error { _, err := f.store.Release(ctx, o.OverrideID, secActor, "", nil); return err },
		"extend":    func() error { _, err := f.store.Extend(ctx, o.OverrideID, time.Hour, secActor, "", nil); return err },
		"permanent": func() error { _, err := f.store.MakePermanent(ctx, o.OverrideID, secActor, "", nil); return err },
	} {
		if err := fn(); !errors.Is(err, ErrConflict) {
			t.Fatalf("%s after release: %v", name, err)
		}
	}
	if _, err := f.store.Release(ctx, "ovr_01HZZZZZZZZZZZZZZZZZZZZZZZ", secActor, "", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown: %v", err)
	}
	if _, err := f.store.Release(ctx, "'; DROP TABLE x", secActor, "", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("malformed id: %v", err)
	}
	for _, ev := range []string{EventExtended, EventMadePermanent, EventReleased} {
		got := f.events(t, ev)
		if len(got) != 1 || got[0]["override_id"] != o.OverrideID {
			t.Fatalf("%s events: %v", ev, got)
		}
	}
	if r := f.events(t, EventReleased)[0]; r["release_reason"] != "fixed" || r["previous_status"] != StatusActive {
		t.Fatalf("released event %v", r)
	}
	if n := f.count(t, `SELECT count(*) FROM diary WHERE event_type LIKE 'override.%' AND actor = $1`, secActor); n != 4 {
		t.Fatalf("override events by actor: %d", n)
	}
	list, err := f.store.List(ctx, ListFilter{Status: StatusReleased})
	if err != nil || len(list) != 1 {
		t.Fatalf("list released: %v %v", list, err)
	}
	if _, err := f.store.List(ctx, ListFilter{Status: "bogus"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad status filter: %v", err)
	}
	f.verifyDiary(t)
}
