package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"fortik/internal/integrations"
	"fortik/internal/memory"
)

func TestStoreAgainstRealPGVector(t *testing.T) {
	e := newEnv(t, envOpts{})
	ctx := context.Background()
	st := e.store(t)

	if st.Dimension() != 0 {
		t.Fatalf("fresh store sized: %d", st.Dimension())
	}
	a, err := st.Write(ctx, memory.Item{Namespace: "kb", Content: "refunds take 5 days", Embedding: []float32{1, 0, 0}, AgentID: supportAgent,
		Metadata: map[string]string{"labels": "faq"}})
	if err != nil {
		t.Fatal(err)
	}
	if !a.Staged || a.ID == "" || a.PromoteAt == nil || a.PromoteAt.Sub(time.Now()) < 9*time.Minute {
		t.Fatalf("write not staged with the promotion delay: %+v", a)
	}
	if st.Dimension() != 3 {
		t.Fatalf("column not sized from the first embedding: %d", st.Dimension())
	}
	if n := e.custCount(t, `SELECT count(*) FROM pg_extension WHERE extname = 'vector'`); n != 1 {
		t.Fatal("vector extension not installed")
	}
	if n := e.custCount(t, `SELECT a.atttypmod FROM pg_attribute a WHERE a.attrelid = 'fortik_memory.items'::regclass AND a.attname = 'embedding'`); n != 3 {
		t.Fatalf("embedding column typmod %d, want 3", n)
	}
	if _, err := st.Write(ctx, memory.Item{Namespace: "kb", Content: "x", Embedding: []float32{1, 2}, AgentID: supportAgent}); !errors.Is(err, memory.ErrInvalid) {
		t.Fatalf("wrong-size embedding accepted: %v", err)
	}
	b, err := st.Write(ctx, memory.Item{Namespace: "kb", Content: "shipping is free over $50", Embedding: []float32{0, 1, 0}, AgentID: otherAgent})
	if err != nil {
		t.Fatal(err)
	}

	// Staged items are visible to their writer only.
	hits, err := st.Search(ctx, memory.SearchRequest{Namespace: "kb", Embedding: []float32{0.9, 0.1, 0}, StagedOf: supportAgent})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 || hits[0].ID != a.ID || hits[0].Distance == nil || *hits[0].Distance > 0.1 {
		t.Fatalf("writer's own staged hit: %+v", hits)
	}
	if hits, _ := st.Search(ctx, memory.SearchRequest{Namespace: "kb", StagedOf: "nobody"}); len(hits) != 0 {
		t.Fatalf("staged items leaked to another agent: %+v", hits)
	}

	// Promotion: due, unflagged, writer not excluded.
	if n, err := st.Promote(ctx, time.Now()); err != nil || n != 0 {
		t.Fatalf("promoted before due: %d %v", n, err)
	}
	p, err := st.PromoteDue(ctx, time.Now().Add(11*time.Minute), []string{otherAgent})
	if err != nil || len(p) != 1 || p[0].ID != a.ID {
		t.Fatalf("promote due: %+v %v", p, err)
	}
	// Nearest neighbour order over promoted items for everyone.
	if _, err := st.PromoteDue(ctx, time.Now().Add(11*time.Minute), nil); err != nil {
		t.Fatal(err)
	}
	hits, err = st.Search(ctx, memory.SearchRequest{Namespace: "kb", Embedding: []float32{0, 1, 0}})
	if err != nil || len(hits) != 2 || hits[0].ID != b.ID {
		t.Fatalf("nearest neighbour order: %+v %v", hits, err)
	}
	// Full-text query.
	hits, err = st.Search(ctx, memory.SearchRequest{Namespace: "kb", Text: "refunds"})
	if err != nil || len(hits) != 1 || hits[0].ID != a.ID {
		t.Fatalf("text query: %+v %v", hits, err)
	}
	// DropStaged refuses a promoted item.
	if err := st.DropStaged(ctx, "kb", a.ID); !errors.Is(err, memory.ErrAlreadyPromoted) {
		t.Fatalf("drop of a promoted item: %v", err)
	}
	// Flag hides an item from agents.
	if err := st.Flag(ctx, "kb", b.ID, "suspicious"); err != nil {
		t.Fatal(err)
	}
	if hits, _ := st.Search(ctx, memory.SearchRequest{Namespace: "kb"}); len(hits) != 1 || hits[0].ID != a.ID {
		t.Fatalf("flagged item still visible: %+v", hits)
	}
	if err := st.Flag(ctx, "kb", "nope", "x"); !errors.Is(err, memory.ErrItemNotFound) {
		t.Fatalf("flag of a missing item: %v", err)
	}

	// Snapshot and restore replace the namespace exactly.
	loc, n, err := st.Snapshot(ctx, "kb")
	if err != nil || n != 2 {
		t.Fatalf("snapshot: %v %d", err, n)
	}
	other, err := st.Write(ctx, memory.Item{Namespace: "other", Content: "unrelated", AgentID: supportAgent})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Delete(ctx, "kb", a.ID); err != nil {
		t.Fatal(err)
	}
	c, err := st.Write(ctx, memory.Item{Namespace: "kb", Content: "later", AgentID: supportAgent})
	if err != nil {
		t.Fatal(err)
	}
	restored, err := st.Restore(ctx, "kb", loc)
	if err != nil || restored != 1 {
		t.Fatalf("restore: %d %v", restored, err)
	}
	if _, err := st.Get(ctx, "kb", c.ID); !errors.Is(err, memory.ErrItemNotFound) {
		t.Fatalf("item written after the snapshot survived the restore: %v", err)
	}
	// A deleted item is tombstoned: a restore does not bring it back.
	if _, err := st.Get(ctx, "kb", a.ID); !errors.Is(err, memory.ErrItemNotFound) {
		t.Fatalf("deleted item came back through a restore: %v", err)
	}
	if got, err := st.Get(ctx, "kb", b.ID); err != nil || !got.Flagged {
		t.Fatalf("flag not restored: %+v %v", got, err)
	}
	if _, err := st.Get(ctx, "other", other.ID); err != nil {
		t.Fatalf("restore touched another namespace: %v", err)
	}
	if _, err := st.Restore(ctx, "other", loc); !errors.Is(err, memory.ErrInvalid) {
		t.Fatalf("snapshot of kb restored into another namespace: %v", err)
	}
	if _, err := st.Restore(ctx, "kb", "public.users"); !errors.Is(err, memory.ErrInvalid) {
		t.Fatalf("arbitrary table accepted as a snapshot location: %v", err)
	}
	if err := st.DropSnapshot(ctx, loc); err != nil {
		t.Fatal(err)
	}
	if err := st.DropSnapshot(ctx, loc); err != nil {
		t.Fatalf("dropping a gone snapshot: %v", err)
	}
	if _, err := st.Restore(ctx, "kb", loc); !errors.Is(err, memory.ErrSnapshotMissing) {
		t.Fatalf("restore of a dropped snapshot: %v", err)
	}
}

func TestStoreConfiguredDimensionAndValidation(t *testing.T) {
	e := newEnv(t, envOpts{dimension: 4})
	ctx := context.Background()
	st := e.store(t)
	if _, err := st.Write(ctx, memory.Item{Namespace: "kb", Content: "x", Embedding: []float32{1, 2, 3}, AgentID: supportAgent}); !errors.Is(err, memory.ErrInvalid) {
		t.Fatalf("embedding of the wrong size accepted: %v", err)
	}
	if st.Dimension() != 4 {
		t.Fatalf("configured dimension not applied: %d", st.Dimension())
	}
	for _, it := range []memory.Item{
		{Namespace: "bad/ns", Content: "x", AgentID: supportAgent},
		{Namespace: "kb", Content: "", AgentID: supportAgent},
		{Namespace: "kb", Content: "x"},
		{Namespace: "kb", Content: "nul\x00", AgentID: supportAgent},
		{Namespace: "kb", ID: "../x", Content: "x", AgentID: supportAgent},
	} {
		if _, err := st.Write(ctx, it); !errors.Is(err, memory.ErrInvalid) {
			t.Fatalf("invalid item accepted: %+v: %v", it, err)
		}
	}
	it, err := st.Write(ctx, memory.Item{ID: "fixed-1", Namespace: "kb", Content: "x", AgentID: supportAgent})
	if err != nil || it.ID != "fixed-1" {
		t.Fatal(err)
	}
	if _, err := st.Write(ctx, memory.Item{ID: "fixed-1", Namespace: "kb", Content: "y", AgentID: otherAgent}); !errors.Is(err, memory.ErrInvalid) {
		t.Fatalf("duplicate id overwrote an item: %v", err)
	}
}

func TestStoresResolution(t *testing.T) {
	e := newEnv(t, envOpts{})
	ctx := context.Background()
	if _, err := e.stores.Store(ctx, "missing"); !errors.Is(err, memory.ErrStoreNotConfigured) || !errors.Is(err, integrations.ErrNotConfigured) {
		t.Fatalf("missing store: %v", err)
	}
	if _, err := e.stores.Store(ctx, "Bad-Name"); !errors.Is(err, memory.ErrInvalid) {
		t.Fatalf("bad store name: %v", err)
	}
	a := e.store(t)
	if b := e.store(t); a != b {
		t.Fatal("pool not reused for unchanged settings")
	}
	names, err := e.stores.Names(ctx)
	if err != nil || len(names) != 1 || names[0] != "support" {
		t.Fatalf("names: %v %v", names, err)
	}
	// A settings change reconnects.
	r := resolvedFor(t, "support", e.custDSN, 8)
	e.src.mu.Lock()
	e.src.m["memory:support"] = r
	e.src.mu.Unlock()
	if c := e.store(t); c == a {
		t.Fatal("store not rebuilt after a settings change")
	}
}

func TestTesterAndSchema(t *testing.T) {
	e := newEnv(t, envOpts{})
	ctx := context.Background()
	r, _ := e.src.Get(ctx, "memory:support")
	if err := (memory.Tester{}).Test(ctx, r); err != nil {
		t.Fatalf("tester on a good store: %v", err)
	}
	bad := resolvedFor(t, "support", e.custDSN+"_missing_db", 0)
	bad.ConfigMap["database"] = "no_such_database_xyz"
	if err := (memory.Tester{}).Test(ctx, bad); err == nil {
		t.Fatal("tester passed against a missing database")
	}
	if _, err := memory.ParseSettings(integrations.Resolved{Integration: integrations.Integration{Key: "memory:x"}, ConfigMap: map[string]any{}}); !errors.Is(err, integrations.ErrInvalid) {
		t.Fatalf("empty settings accepted: %v", err)
	}
	s := memory.Schema()
	if s.System != "memory" || !s.Multi {
		t.Fatalf("schema: %+v", s)
	}
	secret := map[string]bool{}
	for _, f := range s.Fields {
		secret[f.Key] = f.Secret
	}
	for _, k := range []string{"host", "port", "database", "sslmode", "admin_user", "admin_password"} {
		if _, ok := secret[k]; !ok {
			t.Fatalf("schema lacks %s", k)
		}
	}
	if !secret["admin_password"] || secret["admin_user"] {
		t.Fatal("admin_password must be the only secret")
	}
	set, err := memory.ParseSettings(r)
	if err != nil {
		t.Fatal(err)
	}
	if got := set.String(); got == "" || containsSecret(got, r.Secret("admin_password")) {
		t.Fatalf("settings string leaks the password: %q", got)
	}
}

func containsSecret(s, secret string) bool {
	return secret != "" && len(s) >= len(secret) && (func() bool {
		for i := 0; i+len(secret) <= len(s); i++ {
			if s[i:i+len(secret)] == secret {
				return true
			}
		}
		return false
	})()
}
