package queues

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// celeryV2Message builds a task message exactly as Celery 5 (protocol v2)
// sends it over kombu's Redis transport: the envelope kombu stores in the
// list, with the base64 body [args, kwargs, embed] and the task headers.
// Custom apply_async headers (fortik_agent_id) are merged into the headers.
// agent "" builds an untagged message.
func celeryV2Message(t *testing.T, agent, queue string, n int) (raw, id string) {
	t.Helper()
	id = newUUID()
	body, err := json.Marshal([]any{[]any{agent, n}, map[string]any{}, map[string]any{"callbacks": nil, "errbacks": nil, "chain": nil, "chord": nil}})
	if err != nil {
		t.Fatal(err)
	}
	headers := map[string]any{
		"lang": "py", "task": "fortik_test.record", "id": id, "shadow": nil, "eta": nil, "expires": nil,
		"group": nil, "group_index": nil, "retries": 0, "timelimit": []any{nil, nil}, "root_id": id, "parent_id": nil,
		"argsrepr": fmt.Sprintf("('%s', %d)", agent, n), "kwargsrepr": "{}", "origin": "gen1@test",
		"ignore_result": false, "replaced_task_nesting": 0, "stamped_headers": nil, "stamps": map[string]any{},
	}
	if agent != "" {
		headers[CeleryAgentHeader] = agent
	}
	env := map[string]any{
		"body":             base64.StdEncoding.EncodeToString(body),
		"content-encoding": "utf-8",
		"content-type":     "application/json",
		"headers":          headers,
		"properties": map[string]any{
			"correlation_id": id, "reply_to": newUUID(), "delivery_mode": 2,
			"delivery_info": map[string]any{"exchange": "", "routing_key": queue},
			"priority":      0, "body_encoding": "base64", "delivery_tag": newUUID(),
		},
	}
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return string(b), id
}

// envelopeAgent returns the fortik_agent_id header of a stored message, or
// the raw text for anything that is not a Celery envelope.
func envelopeAgent(raw string) string {
	var m struct {
		Headers map[string]any `json:"headers"`
	}
	if json.Unmarshal([]byte(raw), &m) != nil || m.Headers == nil {
		return "raw:" + raw
	}
	if a, ok := m.Headers[CeleryAgentHeader].(string); ok {
		return a
	}
	return "untagged"
}

func envelopeID(t *testing.T, raw string) string {
	t.Helper()
	var m struct {
		Headers struct {
			ID   string `json:"id"`
			Task string `json:"task"`
		} `json:"headers"`
		Properties struct {
			BodyEncoding string `json:"body_encoding"`
		} `json:"properties"`
	}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("not a Celery envelope: %v", err)
	}
	return m.Headers.ID
}

func lrange(t *testing.T, rdb *redis.Client, key string) []string {
	t.Helper()
	v, err := rdb.LRange(context.Background(), key, 0, -1).Result()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// unackedEntry is kombu's "unacked" hash value: [envelope, exchange, routing key].
func unackedEntry(raw, queue string) string {
	return `[` + raw + `,"","` + queue + `"]`
}

// revokeListener subscribes to the pidbox fanout the way a Celery worker
// on kombu's Redis transport does (PSUBSCRIBE /<db>.celery.pidbox) and
// decodes broadcast control commands.
type revokeCmd struct {
	Method    string `json:"method"`
	Arguments struct {
		TaskID    []string `json:"task_id"`
		Terminate bool     `json:"terminate"`
	} `json:"arguments"`
	Destination []string `json:"destination"`
}

func listenPidbox(t *testing.T, rdb *redis.Client) <-chan revokeCmd {
	t.Helper()
	ps := rdb.PSubscribe(context.Background(), CeleryPidboxChannel(0))
	if _, err := ps.Receive(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ps.Close() })
	out := make(chan revokeCmd, 4)
	go func() {
		for msg := range ps.Channel() {
			var env struct {
				Body         string         `json:"body"`
				ContentType  string         `json:"content-type"`
				Headers      map[string]any `json:"headers"`
				Properties   map[string]any `json:"properties"`
				BodyEncoding string
			}
			if json.Unmarshal([]byte(msg.Payload), &env) != nil || env.ContentType != "application/json" ||
				env.Properties["body_encoding"] != "base64" {
				continue
			}
			body, err := base64.StdEncoding.DecodeString(env.Body)
			if err != nil {
				continue
			}
			var cmd revokeCmd
			if json.Unmarshal(body, &cmd) == nil {
				out <- cmd
			}
		}
	}()
	return out
}

func TestCeleryHoldReleaseCancel(t *testing.T) {
	addr := startRedis(t)
	ctx := context.Background()
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() { _ = rdb.Close() })

	src := newSource()
	src.set(t, SystemCelery, map[string]any{"queues": []string{"celery", "bulk"}}, map[string]string{"redis_url": "redis://" + addr + "/0"})
	cel := NewCelery(src)

	// kombu producers LPUSH; the right end is the oldest message.
	push := func(key, raw string) { t.Helper(); rdb.LPush(ctx, key, raw) }
	msg := func(agent, queue string, n int) string { raw, _ := celeryV2Message(t, agent, queue, n); return raw }
	a1, b1, a2 := msg("agent-a", "celery", 1), msg("agent-b", "celery", 1), msg("agent-a", "celery", 2)
	junk, untagged := "not json {", msg("", "celery", 0)
	a3, b2 := msg("agent-a", "celery", 3), msg("agent-b", "celery", 2)
	a4prio, a5bulk := msg("agent-a", "celery", 4), msg("agent-a", "bulk", 5)
	for _, m := range []string{a1, b1, a2, junk, untagged, a3, b2} {
		push("celery", m)
	}
	prio := "celery" + celerySep + "9"
	push(prio, a4prio)
	push("bulk", a5bulk)
	// One message of each agent already fetched by a worker (unacked).
	a6, a6id := celeryV2Message(t, "agent-a", "celery", 6)
	b3, _ := celeryV2Message(t, "agent-b", "celery", 3)
	rdb.HSet(ctx, celeryUnacked, "tag-a6", unackedEntry(a6, "celery"), "tag-b3", unackedEntry(b3, "celery"))
	rdb.ZAdd(ctx, celeryUnackedIdx, redis.Z{Score: 1, Member: "tag-a6"}, redis.Z{Score: 2, Member: "tag-b3"})

	// --- Pause holds only agent-a's waiting messages.
	res, err := cel.Pause(ctx, "agent-a", "suspicious")
	if err != nil {
		t.Fatal(err)
	}
	if res.System != SystemCelery || res.Affected != 5 || !strings.Contains(res.Detail, "held 5 queued messages from 2 queues") ||
		!strings.Contains(res.Detail, "1 message of this agent was already fetched by a worker") {
		t.Fatalf("pause: %+v", res)
	}
	// Everything else is untouched, in order.
	if got, want := lrange(t, rdb, "celery"), []string{b2, untagged, junk, b1}; !slices.Equal(got, want) {
		t.Fatalf("celery after pause: %v", got)
	}
	if n := rdb.LLen(ctx, prio).Val() + rdb.LLen(ctx, "bulk").Val(); n != 0 {
		t.Fatalf("%d agent-a messages left in priority/bulk queues", n)
	}
	if got := lrange(t, rdb, CeleryHeldKey("agent-a", "celery")); !slices.Equal(got, []string{a3, a2, a1}) {
		t.Fatalf("held: %v", got)
	}
	if rdb.HLen(ctx, celeryUnacked).Val() != 2 {
		t.Fatal("pause touched unacked deliveries")
	}
	// A message arriving while paused is held on the next pause (idempotent).
	a7 := msg("agent-a", "celery", 7)
	push("celery", a7)
	if res, err := cel.Pause(ctx, "agent-a", "again"); err != nil || res.Affected != 1 {
		t.Fatalf("second pause: %+v %v", res, err)
	}
	if res, err := cel.Pause(ctx, "agent-a", "again"); err != nil || res.Affected != 0 {
		t.Fatalf("third pause: %+v %v", res, err)
	}

	// --- Resume puts them back at the consuming end, oldest first.
	res, err = cel.Resume(ctx, "agent-a", "cleared")
	if err != nil || res.Affected != 6 || !strings.Contains(res.Detail, "returned 6 held messages") {
		t.Fatalf("resume: %+v %v", res, err)
	}
	var consumed []string
	for {
		v, err := rdb.RPop(ctx, "celery").Result() // BRPOP order
		if errors.Is(err, redis.Nil) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		consumed = append(consumed, v)
	}
	if want := []string{a1, a2, a3, a7, b1, junk, untagged, b2}; !slices.Equal(consumed, want) {
		t.Fatalf("consumption order after resume:\n got %v\nwant %v", consumed, want)
	}
	if got := lrange(t, rdb, prio); !slices.Equal(got, []string{a4prio}) {
		t.Fatalf("priority queue after resume: %v", got)
	}
	if got := lrange(t, rdb, "bulk"); !slices.Equal(got, []string{a5bulk}) {
		t.Fatalf("bulk after resume: %v", got)
	}
	if n, _ := rdb.Keys(ctx, "fortik:held:*").Result(); len(n) != 0 {
		t.Fatalf("held keys left: %v", n)
	}
	rdb.Del(ctx, prio, "bulk")

	// --- Cancel deletes queued, held and unacked messages of agent-a only
	// and broadcasts revoke for their task ids.
	revokes := listenPidbox(t, rdb)
	a8, a8id := celeryV2Message(t, "agent-a", "bulk", 8)
	push("bulk", a8)
	if _, err := cel.Pause(ctx, "agent-a", "hold"); err != nil {
		t.Fatal(err)
	}
	a9, a9id := celeryV2Message(t, "agent-a", "celery", 9)
	b4 := msg("agent-b", "celery", 4)
	push("celery", a9)
	push("celery", b4)
	res, err = cel.Cancel(ctx, "agent-a", "kill")
	if err != nil {
		t.Fatalf("cancel: %v (%+v)", err, res)
	}
	if res.Affected != 3 || !strings.Contains(res.Detail, "deleted 1 queued message, 1 held message and 1 message fetched by workers") ||
		!strings.Contains(res.Detail, "broadcast revoke for 3 task ids to 1 listening worker connection") ||
		!strings.Contains(res.Detail, "not reversible") {
		t.Fatalf("cancel result: %+v", res)
	}
	select {
	case cmd := <-revokes:
		slices.Sort(cmd.Arguments.TaskID)
		want := []string{a6id, a8id, a9id}
		slices.Sort(want)
		if cmd.Method != "revoke" || cmd.Arguments.Terminate || cmd.Destination != nil || !slices.Equal(cmd.Arguments.TaskID, want) {
			t.Fatalf("revoke broadcast: %+v want ids %v", cmd, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no revoke broadcast")
	}
	if got := lrange(t, rdb, "celery"); !slices.Equal(got, []string{b4}) {
		t.Fatalf("celery after cancel: %v", got)
	}
	if n, _ := rdb.Keys(ctx, "fortik:held:*").Result(); len(n) != 0 {
		t.Fatalf("held keys left: %v", n)
	}
	if h := rdb.HKeys(ctx, celeryUnacked).Val(); !slices.Equal(h, []string{"tag-b3"}) {
		t.Fatalf("unacked after cancel: %v", h)
	}
	if z := rdb.ZRange(ctx, celeryUnackedIdx, 0, -1).Val(); !slices.Equal(z, []string{"tag-b3"}) {
		t.Fatalf("unacked index after cancel: %v", z)
	}
	if res, err := cel.Cancel(ctx, "agent-z", "nothing"); err != nil || res.Affected != 0 || !strings.Contains(res.Detail, "nothing to revoke") {
		t.Fatalf("cancel nothing: %+v %v", res, err)
	}
}

func TestCeleryTesterAndRefusals(t *testing.T) {
	addr := startRedis(t, "--requirepass", "broker-pass-123")
	ctx := context.Background()
	src := newSource()
	cel := NewCelery(src)
	if _, err := cel.Pause(ctx, "agent-1", "r"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("not configured: %v", err)
	}
	src.set(t, SystemCelery, map[string]any{}, map[string]string{"redis_url": "redis://:broker-pass-123@" + addr + "/0"})
	r, _ := src.Get(ctx, SystemCelery)
	if err := cel.Test(ctx, r); err != nil {
		t.Fatalf("tester: %v", err)
	}
	// Default queue "celery" when none is configured.
	rdb := redis.NewClient(&redis.Options{Addr: addr, Password: "broker-pass-123"})
	t.Cleanup(func() { _ = rdb.Close() })
	raw, _ := celeryV2Message(t, "agent-1", "celery", 1)
	rdb.LPush(ctx, "celery", raw)
	if res, err := cel.Pause(ctx, "agent-1", "r"); err != nil || res.Affected != 1 {
		t.Fatalf("default queue: %+v %v", res, err)
	}
	for _, bad := range []string{"", "a b", "agent:*", "x'y"} {
		if _, err := cel.Pause(ctx, bad, "r"); err == nil {
			t.Errorf("agent id %q accepted", bad)
		}
	}
	// Errors never contain the broker password.
	for _, u := range []string{"redis://:wrong-pass-456@" + addr + "/0", "redis://:wrong-pass-456@127.0.0.1:1/0", "http://:wrong-pass-456@x/0"} {
		src.set(t, SystemCelery, map[string]any{}, map[string]string{"redis_url": u})
		r, _ := src.Get(ctx, SystemCelery)
		err := cel.Test(ctx, r)
		if err == nil || strings.Contains(err.Error(), "wrong-pass-456") {
			t.Errorf("tester with %s: %v", strings.Replace(u, "wrong-pass-456", "***", 1), err)
		}
		if _, err := cel.Cancel(ctx, "agent-1", "r"); err == nil || strings.Contains(err.Error(), "wrong-pass-456") {
			t.Errorf("cancel with bad broker: %v", err)
		}
	}
}

// --- Real Celery producer and worker (Python venv).

// celeryVenv returns the venv with celery and redis installed, or skips.
func celeryVenv(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("FORTIK_TEST_CELERY_VENV")
	if dir == "" {
		dir = "/private/tmp/fortik-celery-venv"
	}
	if !fileExists(filepath.Join(dir, "bin", "celery")) {
		t.Skipf("real Celery test skipped: no venv at %s (python3 -m venv %s && %s/bin/pip install celery redis, or set FORTIK_TEST_CELERY_VENV)", dir, dir, dir)
	}
	return dir
}

type celeryEnv struct {
	venv, dir, broker, out string
}

func (e celeryEnv) environ(extra ...string) []string {
	return append(append(os.Environ(), "PYTHONDONTWRITEBYTECODE=1", "FORTIK_CELERY_BROKER="+e.broker, "FORTIK_CELERY_OUT="+e.out), extra...)
}

// produce enqueues tasks with Celery's own producer and returns their ids.
func (e celeryEnv) produce(t *testing.T, queue, agent string, first, count int, countdown string) []string {
	t.Helper()
	args := []string{filepath.Join(e.dir, "produce.py"), agent, fmt.Sprint(first), fmt.Sprint(count)}
	if countdown != "" {
		args = append(args, countdown)
	}
	cmd := exec.Command(filepath.Join(e.venv, "bin", "python"), args...)
	cmd.Dir = e.dir
	cmd.Env = e.environ("FORTIK_CELERY_QUEUE=" + queue)
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			t.Fatalf("celery producer: %v\n%s", err, ee.Stderr)
		}
		t.Fatalf("celery producer: %v", err)
	}
	ids := strings.Fields(string(out))
	if len(ids) != count {
		t.Fatalf("producer printed %v", ids)
	}
	return ids
}

func (e celeryEnv) ran(t *testing.T) []string {
	t.Helper()
	f, err := os.Open(e.out)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines
}

func TestCeleryRealWorker(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a real Celery worker")
	}
	venv := celeryVenv(t)
	addr := startRedis(t)
	ctx := context.Background()
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() { _ = rdb.Close() })
	dir, err := filepath.Abs(filepath.Join("testdata", "celery"))
	if err != nil {
		t.Fatal(err)
	}
	env := celeryEnv{venv: venv, dir: dir, broker: "redis://" + addr + "/0", out: filepath.Join(t.TempDir(), "ran.txt")}

	src := newSource()
	src.set(t, SystemCelery, map[string]any{"queues": []string{"celery", "bulk"}}, map[string]string{"redis_url": env.broker})
	cel := NewCelery(src)

	// 1. Genuine producer, no worker yet: the messages carry the header.
	env.produce(t, "celery", "agent-a", 0, 3, "")
	env.produce(t, "celery", "agent-b", 0, 2, "")
	queued := lrange(t, rdb, "celery")
	if len(queued) != 5 {
		t.Fatalf("queued: %d", len(queued))
	}
	agents := map[string]int{}
	for _, raw := range queued {
		if envelopeID(t, raw) == "" {
			t.Fatalf("no task id in %s", raw)
		}
		agents[envelopeAgent(raw)]++
	}
	if agents["agent-a"] != 3 || agents["agent-b"] != 2 {
		t.Fatalf("the Celery producer did not put fortik_agent_id in the protocol v2 headers: %v", agents)
	}

	// 2. Pause agent-a, then start a real worker: only agent-b's tasks run.
	if res, err := cel.Pause(ctx, "agent-a", "suspicious"); err != nil || res.Affected != 3 {
		t.Fatalf("pause: %+v %v", res, err)
	}
	worker := exec.Command(filepath.Join(venv, "bin", "celery"), "-A", "fortik_tasks", "worker", "-P", "solo", "-Q", "celery",
		"-n", "fortik-test@localhost", "--without-mingle", "--without-gossip", "--without-heartbeat", "-l", "info")
	worker.Dir = dir
	worker.Env = env.environ()
	wout := &syncBuffer{}
	worker.Stdout, worker.Stderr = wout, wout
	if err := worker.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = worker.Process.Kill()
		_, _ = worker.Process.Wait()
		if t.Failed() {
			t.Logf("celery worker output:\n%s", wout.String())
		}
	})
	waitFor(t, "worker listening for broadcasts", 60*time.Second, func() bool {
		n, err := rdb.PubSubNumPat(ctx).Result()
		return err == nil && n > 0
	})
	waitFor(t, "agent-b's tasks", 30*time.Second, func() bool { return len(env.ran(t)) >= 2 })
	time.Sleep(time.Second)
	if got := env.ran(t); !slices.Equal(got, []string{"agent-b 0", "agent-b 1"}) {
		t.Fatalf("ran while agent-a paused: %v", got)
	}

	// 3. Resume: agent-a's held tasks run, in their original order.
	if res, err := cel.Resume(ctx, "agent-a", "cleared"); err != nil || res.Affected != 3 {
		t.Fatalf("resume: %+v %v", res, err)
	}
	waitFor(t, "agent-a's tasks", 30*time.Second, func() bool { return len(env.ran(t)) >= 5 })
	if got := env.ran(t)[2:]; !slices.Equal(got, []string{"agent-a 0", "agent-a 1", "agent-a 2"}) {
		t.Fatalf("after resume: %v", got)
	}

	// 4. Cancel: tasks the worker already reserved (countdown, so they sit
	// in worker memory and Redis's unacked hash) must be dropped by the
	// worker after the revoke broadcast; queued and held ones are deleted.
	reserved := env.produce(t, "celery", "agent-a", 10, 2, "6")
	env.produce(t, "celery", "agent-b", 10, 1, "6")
	env.produce(t, "bulk", "agent-a", 20, 1, "") // no worker consumes "bulk"
	if res, err := cel.Pause(ctx, "agent-a", "hold"); err != nil || res.Affected != 1 {
		t.Fatalf("pause bulk: %+v %v", res, err)
	}
	env.produce(t, "bulk", "agent-a", 21, 1, "")
	env.produce(t, "bulk", "agent-b", 20, 1, "")
	waitFor(t, "worker reserved the countdown tasks", 30*time.Second, func() bool { return rdb.HLen(ctx, celeryUnacked).Val() == 3 })
	res, err := cel.Cancel(ctx, "agent-a", "kill")
	if err != nil {
		t.Fatalf("cancel: %v (%+v)", err, res)
	}
	if res.Affected != 4 || !strings.Contains(res.Detail, "deleted 1 queued message, 1 held message and 2 messages fetched by workers") ||
		!strings.Contains(res.Detail, "broadcast revoke for 4 task ids to 1 listening worker connection") {
		t.Fatalf("cancel result: %+v", res)
	}
	waitFor(t, "agent-b's countdown task", 30*time.Second, func() bool { return slices.Contains(env.ran(t), "agent-b 10") })
	time.Sleep(1500 * time.Millisecond)
	for _, line := range env.ran(t) {
		if slices.Contains([]string{"agent-a 10", "agent-a 11", "agent-a 20", "agent-a 21"}, line) {
			t.Fatalf("cancelled task ran: %q (all: %v)", line, env.ran(t))
		}
	}
	for _, id := range reserved {
		if !strings.Contains(wout.String(), "Discarding revoked task: fortik_test.record["+id+"]") {
			t.Errorf("worker log does not show task %s discarded as revoked", id)
		}
	}
	bulk := lrange(t, rdb, "bulk")
	if len(bulk) != 1 || envelopeAgent(bulk[0]) != "agent-b" {
		t.Fatalf("bulk after cancel: %v", bulk)
	}
}
