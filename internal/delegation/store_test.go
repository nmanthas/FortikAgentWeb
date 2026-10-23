package delegation_test

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"fortik/internal/delegation"
)

func TestSigningKeyAutoCreatedAndReused(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	key, err := f.sec.Get(ctx, keySecret)
	if err != nil {
		t.Fatalf("key not created: %v", err)
	}
	if len(key) != 32 || bytes.Equal(key, make([]byte, 32)) {
		t.Fatalf("bad generated key length %d", len(key))
	}
	_, tok, err := f.store.Open(ctx, delegation.Hop{From: "agent_a", To: "agent_b", Chain: []string{"agent_a", "agent_b"}, Channel: "a2a"})
	if err != nil {
		t.Fatal(err)
	}
	// A second store (another Fortik process) loads the same key and verifies.
	other, err := delegation.NewPGStore(ctx, f.pool, f.d, f.sec, f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Verify(ctx, tok, "agent_b"); err != nil {
		t.Fatalf("second store cannot verify: %v", err)
	}
	again, _ := f.sec.Get(ctx, keySecret)
	if !bytes.Equal(again, key) {
		t.Fatal("existing key was replaced")
	}
	// A different key (rotation) invalidates outstanding tokens.
	sec2 := newSecrets(t)
	rotated, err := delegation.NewPGStore(ctx, f.pool, f.d, sec2, f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotated.Verify(ctx, tok, "agent_b"); !errors.Is(err, delegation.ErrInvalidToken) {
		t.Fatalf("other key: %v", err)
	}
}

func TestSigningKeyFailsClosed(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	sec := newSecrets(t)
	if err := sec.Put(ctx, "short", []byte("too-short")); err != nil {
		t.Fatal(err)
	}
	cfg := f.cfg
	cfg.SigningKeySecret = "short"
	if _, err := delegation.NewPGStore(ctx, f.pool, f.d, sec, cfg); err == nil {
		t.Fatal("short key accepted")
	}
	cfg.SigningKeySecret = ""
	if _, err := delegation.NewPGStore(ctx, f.pool, f.d, sec, cfg); err == nil {
		t.Fatal("empty secret name accepted")
	}
	cfg.SigningKeySecret = "../escape"
	if _, err := delegation.NewPGStore(ctx, f.pool, f.d, sec, cfg); err == nil {
		t.Fatal("invalid secret name accepted")
	}
}

func TestOpenVerifyInboundClose(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	h1, tok1, err := f.store.Open(ctx, delegation.Hop{From: "agent_a", To: "agent_b", Chain: []string{"agent_a", "agent_b"},
		Channel: "a2a", TaskID: "task-1"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h1.DelegationID, "dlg_") || h1.Root != "agent_a" || h1.Depth != 1 || h1.Status != "open" ||
		!h1.ExpiresAt.Equal(f.clock.Now().Add(15*time.Minute)) {
		t.Fatalf("hop: %+v", h1)
	}
	c, err := f.store.Verify(ctx, tok1, "agent_b")
	if err != nil {
		t.Fatal(err)
	}
	if c.DelegationID != h1.DelegationID || c.Root != "agent_a" || c.Depth != 1 || c.TaskID != "task-1" {
		t.Fatalf("claims: %+v", c)
	}
	if _, err := f.store.Verify(ctx, tok1, "agent_a"); !errors.Is(err, delegation.ErrTokenAgent) {
		t.Fatalf("wrong holder: %v", err)
	}

	// B delegates on to C under h1.
	h2, tok2, err := f.store.Open(ctx, delegation.Hop{ParentID: h1.DelegationID, From: "agent_b", To: "agent_c",
		Chain: []string{"agent_a", "agent_b", "agent_c"}, Channel: "a2a"})
	if err != nil {
		t.Fatal(err)
	}
	if h2.Depth != 2 || h2.Root != "agent_a" || h2.ParentID != h1.DelegationID {
		t.Fatalf("hop 2: %+v", h2)
	}
	in, err := f.store.OpenInbound(ctx, "agent_c")
	if err != nil || len(in) != 1 || in[0].DelegationID != h2.DelegationID || !slices.Equal(in[0].Chain, h2.Chain) {
		t.Fatalf("inbound: %+v %v", in, err)
	}

	// Diary: delegation.opened with chain/root/from/to/channel/depth, no token.
	ev := f.events(t, delegation.EventOpened)
	if len(ev) != 2 {
		t.Fatalf("opened events: %v", ev)
	}
	e := ev[1]
	if e["delegation_id"] != h2.DelegationID || e["root"] != "agent_a" || e["from"] != "agent_b" || e["to"] != "agent_c" ||
		e["channel"] != "a2a" || e["depth"] != float64(2) || len(e["chain"].([]any)) != 3 {
		t.Fatalf("opened event: %v", e)
	}
	for k := range e {
		if strings.Contains(strings.ToLower(k), "token") {
			t.Fatalf("event carries %s", k)
		}
	}

	if err := f.store.Close(ctx, h2.DelegationID, "task completed"); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Close(ctx, h2.DelegationID, "again"); err != nil {
		t.Fatalf("closing a closed hop: %v", err)
	}
	if err := f.store.Close(ctx, "dlg_missing", "x"); !errors.Is(err, delegation.ErrNotFound) {
		t.Fatalf("unknown: %v", err)
	}
	if err := f.store.Close(ctx, h1.DelegationID, " "); err == nil {
		t.Fatal("empty reason accepted")
	}
	if in, _ := f.store.OpenInbound(ctx, "agent_c"); len(in) != 0 {
		t.Fatalf("closed hop still inbound: %v", in)
	}
	got, err := f.store.Get(ctx, h2.DelegationID)
	if err != nil || got.Status != "closed" || got.ClosedAt == nil {
		t.Fatalf("closed hop: %+v %v", got, err)
	}
	cl := f.events(t, delegation.EventClosed)
	if len(cl) != 1 || cl[0]["delegation_id"] != h2.DelegationID || cl[0]["reason"] != "task completed" || cl[0]["root"] != "agent_a" {
		t.Fatalf("closed events: %v", cl)
	}
	f.assertNoToken(t, tok1, tok2)
}

func TestOpenValidation(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	cases := map[string]delegation.Hop{
		"chain end":     {From: "agent_a", To: "agent_b", Chain: []string{"agent_a", "agent_c"}, Channel: "a2a"},
		"from mismatch": {From: "agent_x", To: "agent_b", Chain: []string{"agent_a", "agent_b"}, Channel: "a2a"},
		"short chain":   {From: "agent_a", To: "agent_a", Chain: []string{"agent_a"}, Channel: "a2a"},
		"channel":       {From: "agent_a", To: "agent_b", Chain: []string{"agent_a", "agent_b"}, Channel: "email"},
		"bad id":        {From: "agent a", To: "agent_b", Chain: []string{"agent a", "agent_b"}, Channel: "a2a"},
		"task control":  {From: "agent_a", To: "agent_b", Chain: []string{"agent_a", "agent_b"}, Channel: "a2a", TaskID: "a\nb"},
		"depth range":   {From: "agent_a", To: "agent_b", Chain: []string{"agent_a", "agent_b"}, Channel: "a2a", Depth: 2},
		"beyond max": {From: "agent_f", To: "agent_g", Channel: "a2a",
			Chain: []string{"agent_a", "agent_b", "agent_c", "agent_d", "agent_e", "agent_f", "agent_g"}},
	}
	for name, h := range cases {
		if _, _, err := f.store.Open(ctx, h); !errors.Is(err, delegation.ErrInvalidHop) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n := f.count(t, `SELECT count(*) FROM delegations`); n != 0 {
		t.Fatalf("invalid hops stored: %d", n)
	}
}

func TestExpiryAndCloseTask(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	h1, tok, err := f.store.Open(ctx, delegation.Hop{From: "agent_a", To: "agent_b", Chain: []string{"agent_a", "agent_b"}, Channel: "a2a", TaskID: "t-1"})
	if err != nil {
		t.Fatal(err)
	}
	h2, _, err := f.store.Open(ctx, delegation.Hop{From: "agent_c", To: "agent_b", Chain: []string{"agent_c", "agent_b"}, Channel: "a2a", TaskID: "t-2"})
	if err != nil {
		t.Fatal(err)
	}
	n, err := f.store.CloseTask(ctx, "agent_c", "agent_b", "t-2", "task completed")
	if err != nil || n != 1 {
		t.Fatalf("close task: %d %v", n, err)
	}
	if n, _ := f.store.CloseTask(ctx, "agent_c", "agent_b", "t-2", "again"); n != 0 {
		t.Fatalf("close task twice: %d", n)
	}
	if got, _ := f.store.Get(ctx, h2.DelegationID); got.Status != "closed" {
		t.Fatalf("t-2: %+v", got)
	}

	f.clock.Advance(16 * time.Minute)
	if in, _ := f.store.OpenInbound(ctx, "agent_b"); len(in) != 0 {
		t.Fatalf("expired hop still inbound: %v", in)
	}
	if _, err := f.store.Verify(ctx, tok, "agent_b"); !errors.Is(err, delegation.ErrExpiredToken) {
		t.Fatalf("expired token: %v", err)
	}
	n, err = f.store.ExpireDue(ctx, 10)
	if err != nil || n != 1 {
		t.Fatalf("expire: %d %v", n, err)
	}
	if got, _ := f.store.Get(ctx, h1.DelegationID); got.Status != "expired" {
		t.Fatalf("h1: %+v", got)
	}
	if n, _ := f.store.ExpireDue(ctx, 10); n != 0 {
		t.Fatalf("second sweep: %d", n)
	}
	cl := f.events(t, delegation.EventClosed)
	if len(cl) != 2 || cl[1]["status"] != "expired" || cl[1]["delegation_id"] != h1.DelegationID {
		t.Fatalf("closed events: %v", cl)
	}

	// The worker runs and stops with its context.
	_, _, _ = f.store.Open(ctx, delegation.Hop{From: "agent_a", To: "agent_d", Chain: []string{"agent_a", "agent_d"}, Channel: "a2a"})
	f.clock.Advance(16 * time.Minute)
	wctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { f.store.RunExpiry(wctx, 10*time.Millisecond); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for f.count(t, `SELECT count(*) FROM delegations WHERE status = 'open'`) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("worker did not expire the hop")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
}

func TestList(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	h1, _, _ := f.store.Open(ctx, delegation.Hop{From: "agent_a", To: "agent_b", Chain: []string{"agent_a", "agent_b"}, Channel: "a2a"})
	f.clock.Advance(time.Second)
	_, _, _ = f.store.Open(ctx, delegation.Hop{ParentID: h1.DelegationID, From: "agent_b", To: "agent_c", Chain: []string{"agent_a", "agent_b", "agent_c"}, Channel: "a2a"})
	for _, c := range []struct {
		agent, dir string
		want       int
	}{{"agent_b", "inbound", 1}, {"agent_b", "outbound", 1}, {"agent_a", "all", 2}, {"agent_c", "outbound", 0}} {
		got, err := f.store.List(ctx, c.agent, c.dir, "", 0)
		if err != nil || len(got) != c.want {
			t.Errorf("%s %s: %d %v", c.agent, c.dir, len(got), err)
		}
	}
	if _, err := f.store.List(ctx, "agent_a", "sideways", "", 0); err == nil {
		t.Fatal("bad direction accepted")
	}
}
