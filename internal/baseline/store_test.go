package baseline_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"fortik/internal/baseline"
	"fortik/internal/config"
)

const redisBinary = "/opt/homebrew/bin/redis-server"

// startRedis runs a real redis-server on a free port for the test and kills
// it afterwards. Skips (explicitly) only if the binary is missing.
func startRedis(t *testing.T) string {
	t.Helper()
	if _, err := os.Stat(redisBinary); err != nil {
		t.Skipf("redis test skipped: %s not found (install redis to run it)", redisBinary)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	cmd := exec.Command(redisBinary, "--port", fmt.Sprint(port), "--bind", "127.0.0.1", "--save", "", "--appendonly", "no",
		"--dir", t.TempDir(), "--protected-mode", "yes")
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	url := fmt.Sprintf("redis://127.0.0.1:%d/0", port)
	c := redis.NewClient(&redis.Options{Addr: fmt.Sprintf("127.0.0.1:%d", port)})
	defer c.Close()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if err := c.Ping(context.Background()).Err(); err == nil {
			return url
		}
		if time.Now().After(deadline) {
			t.Fatal("redis-server did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// storeContract exercises the semantics every Store must have.
func storeContract(t *testing.T, s baseline.Store, other baseline.Store) {
	t.Helper()
	ctx := context.Background()
	h0 := nowHour
	// Concurrent adds are exact (and visible from a second client).
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		st := s
		if i%2 == 1 {
			st = other
		}
		go func() {
			defer wg.Done()
			if err := st.Add(ctx, "agent_a", "READ", h0, 1); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n, err := other.Get(ctx, "agent_a", "READ", h0); err != nil || n != 200 {
		t.Fatalf("get %d %v", n, err)
	}
	if n, err := s.Get(ctx, "agent_a", "WRITE", h0); err != nil || n != 0 {
		t.Fatalf("absent verb %d %v", n, err)
	}
	if n, err := s.Get(ctx, "nobody", "READ", h0); err != nil || n != 0 {
		t.Fatalf("absent agent %d %v", n, err)
	}
	if err := s.Add(ctx, "agent_a", "READ", h0-hr, 7); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(ctx, "agent_a", "SEND", h0-3*hr, 2); err != nil {
		t.Fatal(err)
	}
	ser, err := s.Series(ctx, "agent_a", "READ", h0-24*hr)
	if err != nil || len(ser) != 2 || ser[h0] != 200 || ser[h0-hr] != 7 {
		t.Fatalf("series %v %v", ser, err)
	}
	if ser, _ := s.Series(ctx, "agent_a", "READ", h0); len(ser) != 1 {
		t.Fatalf("series from filter: %v", ser)
	}
	if v, err := other.Verbs(ctx, "agent_a"); err != nil || strings.Join(v, ",") != "READ,SEND" {
		t.Fatalf("verbs %v %v", v, err)
	}
	// Merge never lowers a hot count; it raises lower ones and adds absent hours.
	err = s.Merge(ctx, []baseline.Row{
		{AgentID: "agent_a", Verb: "READ", Hour: h0, Count: 5},
		{AgentID: "agent_a", Verb: "READ", Hour: h0 - hr, Count: 9},
		{AgentID: "agent_a", Verb: "READ", Hour: h0 - 2*hr, Count: 4},
		{AgentID: "agent_b", Verb: "DELETE", Hour: h0 - 5*hr, Count: 3},
	})
	if err != nil {
		t.Fatal(err)
	}
	ser, _ = other.Series(ctx, "agent_a", "READ", 0)
	if ser[h0] != 200 || ser[h0-hr] != 9 || ser[h0-2*hr] != 4 {
		t.Fatalf("after merge %v", ser)
	}
	if v, _ := other.Verbs(ctx, "agent_b"); strings.Join(v, ",") != "DELETE" {
		t.Fatalf("merge verbs %v", v)
	}
	// Bad keys are refused, never stored.
	if err := s.Add(ctx, "", "READ", h0, 1); !errors.Is(err, baseline.ErrStoreUnavailable) {
		t.Fatalf("empty agent: %v", err)
	}
	if err := s.Add(ctx, strings.Repeat("x", 300), "READ", h0, 1); !errors.Is(err, baseline.ErrStoreUnavailable) {
		t.Fatalf("long agent: %v", err)
	}
}

func TestMemoryStore(t *testing.T) {
	m := baseline.NewMemoryStore()
	storeContract(t, m, m)
	ctx := context.Background()
	if err := m.Prune(ctx, nowHour-hr); err != nil {
		t.Fatal(err)
	}
	ser, _ := m.Series(ctx, "agent_a", "READ", 0)
	if len(ser) != 2 || ser[nowHour-2*hr] != 0 {
		t.Fatalf("prune: %v", ser)
	}
	if v, _ := m.Verbs(ctx, "agent_b"); len(v) != 0 {
		t.Fatalf("pruned agent still listed: %v", v)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := m.Add(cctx, "a", "READ", nowHour, 1); !errors.Is(err, baseline.ErrStoreUnavailable) {
		t.Fatalf("cancelled: %v", err)
	}
}

// Real redis-server: the same contract with two clients (two Fortik
// processes), expiry set, old fields dropped on the first write of an hour,
// and an unreachable Redis fails closed.
func TestRedisStore(t *testing.T) {
	url := startRedis(t)
	ctx := context.Background()
	s1, err := baseline.NewStore(ctx, config.CountersConfig{Provider: "redis", RedisURL: url}, plan)
	if err != nil {
		t.Fatal(err)
	}
	defer s1.Close()
	s2, err := baseline.NewRedisStore(url, plan.Retention())
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	storeContract(t, s1, s2)

	raw := redis.NewClient(&redis.Options{Addr: strings.TrimSuffix(strings.TrimPrefix(url, "redis://"), "/0")})
	defer raw.Close()
	ttl, err := raw.TTL(ctx, "fortik:bl:h:READ:agent_a").Result()
	if err != nil || ttl <= 14*24*time.Hour || ttl > plan.Retention() {
		t.Fatalf("ttl %v %v", ttl, err)
	}
	// A field older than the retention is dropped by the first write of a new hour.
	old := nowHour - int64(plan.Retention().Seconds()) - hr
	if err := s2.Merge(ctx, []baseline.Row{{AgentID: "agent_a", Verb: "READ", Hour: old, Count: 50}}); err != nil {
		t.Fatal(err)
	}
	if ser, _ := s1.Series(ctx, "agent_a", "READ", 0); ser[old] != 50 {
		t.Fatalf("merged old field missing: %v", ser)
	}
	if err := s1.Add(ctx, "agent_a", "READ", nowHour+hr, 1); err != nil {
		t.Fatal(err)
	}
	if ser, _ := s1.Series(ctx, "agent_a", "READ", 0); ser[old] != 0 || ser[nowHour] != 200 || ser[nowHour+hr] != 1 {
		t.Fatalf("old field not dropped: %v", ser)
	}
}

func TestRedisStoreUnavailableFailsClosed(t *testing.T) {
	ctx := context.Background()
	s, err := baseline.NewRedisStore("redis://127.0.0.1:1/0", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Add(ctx, "a", "READ", nowHour, 1); !errors.Is(err, baseline.ErrStoreUnavailable) {
		t.Fatalf("add: %v", err)
	}
	if _, err := s.Get(ctx, "a", "READ", nowHour); !errors.Is(err, baseline.ErrStoreUnavailable) {
		t.Fatalf("get: %v", err)
	}
	if _, err := s.Series(ctx, "a", "READ", 0); !errors.Is(err, baseline.ErrStoreUnavailable) {
		t.Fatalf("series: %v", err)
	}
	if _, err := baseline.NewStore(ctx, config.CountersConfig{Provider: "redis", RedisURL: "redis://127.0.0.1:1/0"}, plan); err == nil {
		t.Fatal("NewStore must refuse an unreachable redis")
	}
	if _, err := baseline.NewRedisStore("://user:hunter2@nowhere", time.Hour); err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("bad url error must not echo the url: %v", err)
	}
	if _, err := baseline.NewStore(ctx, config.CountersConfig{Provider: "bogus"}, plan); err == nil {
		t.Fatal("unknown provider accepted")
	}
	if st, err := baseline.NewStore(ctx, config.CountersConfig{}, plan); err != nil {
		t.Fatal(err)
	} else if _, ok := st.(*baseline.MemoryStore); !ok {
		t.Fatalf("default provider: %T", st)
	}
}
