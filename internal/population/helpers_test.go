package population_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"fortik/internal/alerts"
	"fortik/internal/config"
	"fortik/internal/control"
	"fortik/internal/diary"
	"fortik/internal/population"
	"fortik/internal/testutil"
)

const redisBinary = "/opt/homebrew/bin/redis-server"

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

type fixture struct {
	pool   *pgxpool.Pool
	d      *diary.Diary
	ctl    *control.Store
	alerts *alerts.PGStore
	svc    *population.Service
	ctr    population.Counters
}

func newFixture(t *testing.T, ctr population.Counters, cfg config.PopulationConfig) fixture {
	t.Helper()
	pool, _ := testutil.FortikDB(t)
	d := diary.New(pool)
	al := alerts.NewPGStore(pool, d)
	if ctr == nil {
		ctr = population.NewMemoryCounters()
	}
	svc, err := population.New(pool, d, al, ctr, cfg, discard())
	if err != nil {
		t.Fatal(err)
	}
	return fixture{pool: pool, d: d, ctl: control.NewStore(pool, d), alerts: al, svc: svc, ctr: ctr}
}

func (f fixture) agent(t *testing.T, id, typ, sponsor string, copyCap int, requireInstances bool) {
	t.Helper()
	ctx := context.Background()
	if _, err := f.ctl.Register(ctx, control.Agent{AgentID: id, Type: typ, Sponsor: sponsor, CopyCap: copyCap}, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE agents SET copy_cap = $2, require_instances = $3 WHERE agent_id = $1`, id, copyCap, requireInstances); err != nil {
		t.Fatal(err)
	}
}

func (f fixture) agentType(t *testing.T, at population.AgentType) {
	t.Helper()
	if _, err := f.svc.PutAgentType(context.Background(), at, "user:sec@acme.com", "test"); err != nil {
		t.Fatal(err)
	}
}

func (f fixture) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// diaryData returns the data of every Diary event of type ev, oldest first.
func (f fixture) diaryData(t *testing.T, ev string) []map[string]any {
	t.Helper()
	rows, err := f.pool.Query(context.Background(), `SELECT body_json FROM diary WHERE event_type = $1 ORDER BY seq`, ev)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var body string
		if err := rows.Scan(&body); err != nil {
			t.Fatal(err)
		}
		var b struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal([]byte(body), &b); err != nil {
			t.Fatal(err)
		}
		out = append(out, b.Data)
	}
	return out
}

// startRedis runs a real redis-server on a free port for the test and
// kills it afterwards. Skips (explicitly) only if the binary is missing.
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

func repoPolicies() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..", "policies")
}

var ruleSystemsRe = regexp.MustCompile(`(?m)^rule_systems := \{([^}]*)\}`)

// policyBundle copies the repo bundle to a temp dir. Spawn registrations are
// decided on system "agents", which needs "agents" in
// data.fortik.config.known_systems (policies/fortik/data.json) and in
// rule_systems (rules/common.rego); both files are owned by other
// workstreams. If either lacks "agents" the COPY is amended (a no-op once
// the real files carry it) and the test logs it.
func policyBundle(t *testing.T) string {
	t.Helper()
	src := repoPolicies()
	dst := filepath.Join(t.TempDir(), "policies")
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if strings.HasSuffix(p, "_test.rego") {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	dataPath := filepath.Join(dst, "fortik", "data.json")
	var data map[string]any
	b, err := os.ReadFile(dataPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &data); err != nil {
		t.Fatal(err)
	}
	cfg := data["config"].(map[string]any)
	known := cfg["known_systems"].([]any)
	has := false
	for _, s := range known {
		has = has || s == "agents"
	}
	if !has {
		t.Log(`test bundle: adding "agents" to config.known_systems (contract change pending in policies/fortik/data.json)`)
		cfg["known_systems"] = append(known, "agents")
		b, _ = json.MarshalIndent(data, "", "  ")
		if err := os.WriteFile(dataPath, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	commonPath := filepath.Join(dst, "fortik", "rules", "common.rego")
	c, err := os.ReadFile(commonPath)
	if err != nil {
		t.Fatal(err)
	}
	m := ruleSystemsRe.FindSubmatch(c)
	if m == nil {
		t.Fatal("rules/common.rego: rule_systems not found")
	}
	if !strings.Contains(string(m[1]), `"agents"`) {
		t.Log(`test bundle: adding "agents" to rule_systems (owned by the hook workstream)`)
		c = ruleSystemsRe.ReplaceAll(c, []byte(`rule_systems := {$1, "agents"}`))
		if err := os.WriteFile(commonPath, c, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}
