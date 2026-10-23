package queues

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"fortik/internal/integrations"
)

// staticSource serves integrations the way PGStore does: config goes
// through JSON (lists become []any, numbers float64).
type staticSource struct {
	mu sync.Mutex
	m  map[string]integrations.Resolved
}

func newSource() *staticSource { return &staticSource{m: map[string]integrations.Resolved{}} }

func (s *staticSource) set(t *testing.T, key string, cfg map[string]any, secrets map[string]string) {
	t.Helper()
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r := integrations.Resolved{Integration: integrations.Integration{Key: key, System: key, Config: b, Status: integrations.StatusConfigured}, Secrets: secrets}
	if err := json.Unmarshal(b, &r.ConfigMap); err != nil {
		t.Fatal(err)
	}
	for k := range secrets {
		r.SecretFields = append(r.SecretFields, k)
	}
	s.mu.Lock()
	s.m[key] = r
	s.mu.Unlock()
}

func (s *staticSource) Get(_ context.Context, key string) (integrations.Resolved, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.m[key]
	if !ok {
		return integrations.Resolved{}, fmt.Errorf("%w: %s", integrations.ErrNotConfigured, key)
	}
	return r, nil
}

func (s *staticSource) List(ctx context.Context, system string) ([]integrations.Resolved, error) {
	r, err := s.Get(ctx, system)
	if err != nil {
		return []integrations.Resolved{}, nil
	}
	return []integrations.Resolved{r}, nil
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// findBinary returns the path of a real server binary or skips the test
// with an explicit message.
func findBinary(t *testing.T, env, name string) string {
	t.Helper()
	if p := os.Getenv(env); p != "" {
		return p
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	if p := filepath.Join("/opt/homebrew/bin", name); fileExists(p) {
		return p
	}
	t.Skipf("integration test skipped: %s not found (install it or set %s)", name, env)
	return ""
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func waitTCP(t *testing.T, addr string, d time.Duration, out fmt.Stringer) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s did not start listening within %s:\n%s", addr, d, out.String())
}

// syncBuffer is a goroutine-safe buffer for process output. The buffer is
// not embedded: exec would otherwise use its unlocked ReadFrom.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// startProcess starts a server process killed on cleanup.
func startProcess(t *testing.T, bin string, args ...string) (*exec.Cmd, *syncBuffer) {
	t.Helper()
	out := &syncBuffer{}
	cmd := exec.Command(bin, args...)
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", bin, err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	return cmd, out
}

// startRedis runs a throwaway redis-server on a free port (no persistence).
func startRedis(t *testing.T, extra ...string) string {
	t.Helper()
	bin := findBinary(t, "FORTIK_TEST_REDIS_SERVER", "redis-server")
	port := freePort(t)
	args := append([]string{"--port", strconv.Itoa(port), "--bind", "127.0.0.1", "--save", "", "--appendonly", "no", "--dir", t.TempDir()}, extra...)
	_, out := startProcess(t, bin, args...)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	waitTCP(t, addr, 10*time.Second, out)
	return addr
}
