package hook

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sampleEvent = `{"session_id":"s1","transcript_path":"/tmp/t.jsonl","cwd":"/work/app","permission_mode":"default","hook_event_name":"PreToolUse","tool_use_id":"tu1","tool_name":"Bash","tool_input":{"command":"ls -la"}}`

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func run(t *testing.T, stdin io.Reader, env map[string]string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := RunClaudeCode(stdin, &out, &errb, envOf(env))
	return code, out.String(), errb.String()
}

func fakeGateway(t *testing.T, status int, body string, check func(*http.Request)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if check != nil {
			check(r)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func baseEnv(url string) map[string]string {
	return map[string]string{"FORTIK_GATEWAY_URL": url, "FORTIK_AGENT_TOKEN": "tok-test"}
}

func TestClientAllow(t *testing.T) {
	var got map[string]json.RawMessage
	srv := fakeGateway(t, 200, `{"decision":"allow","class":"green","rule_id":"POL-000","reason":"ok","action_id":"a1"}`, func(r *http.Request) {
		if r.URL.Path != ClientPath || r.Method != http.MethodPost {
			t.Errorf("path %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer tok-test" || r.Header.Get("X-Fortik-Instance-Id") != "inst-1" || r.Header.Get("X-Fortik-Delegation") != "dlg-tok" {
			t.Errorf("headers %v", r.Header)
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
	})
	env := baseEnv(srv.URL)
	env["FORTIK_INSTANCE_ID"] = "inst-1"
	env["FORTIK_DELEGATION"] = "dlg-tok"
	env["PGHOST"] = "127.0.0.1"
	env["PGPORT"] = "6432"
	env["HOME"] = "/home/dev"
	env["SECRET_THING"] = "nope"
	code, out, errs := run(t, strings.NewReader(sampleEvent), env)
	if code != 0 || out != "" || errs != "" {
		t.Fatalf("allow: code=%d out=%q err=%q", code, out, errs)
	}
	var hints map[string]string
	_ = json.Unmarshal(got["env"], &hints)
	if hints["PGHOST"] != "127.0.0.1" || hints["PGPORT"] != "6432" || hints["HOME"] != "/home/dev" || hints["SECRET_THING"] != "" {
		t.Fatalf("env hints %v", hints)
	}
	if !json.Valid(got["event"]) || !strings.Contains(string(got["event"]), "PreToolUse") {
		t.Fatalf("event not forwarded: %s", got["event"])
	}
}

func TestClientAllowReduced(t *testing.T) {
	srv := fakeGateway(t, 200, `{"decision":"allow_reduced","class":"yellow","rule_id":"POL-302","reason":"r","action_id":"a2","reduced_form":{"record_ref":true}}`, nil)
	code, out, _ := run(t, strings.NewReader(sampleEvent), baseEnv(srv.URL))
	var m map[string]string
	if code != 0 || json.Unmarshal([]byte(out), &m) != nil || !strings.Contains(m["systemMessage"], "record_ref") || len(m) != 1 {
		t.Fatalf("allow_reduced: code=%d out=%q", code, out)
	}
}

func TestClientHoldAndDeny(t *testing.T) {
	for _, d := range []string{"hold", "deny"} {
		srv := fakeGateway(t, 200, `{"decision":"`+d+`","class":"red","rule_id":"POL-501","reason":"direct db\nsecond line","action_id":"act_9"}`, nil)
		code, out, errs := run(t, strings.NewReader(sampleEvent), baseEnv(srv.URL))
		want := "fortik: " + d + " (red) by POL-501: direct db second line action_id=act_9\n"
		if code != 2 || out != "" || errs != want {
			t.Fatalf("%s: code=%d out=%q err=%q", d, code, out, errs)
		}
	}
}

func assertFailClosed(t *testing.T, name string, code int, out, errs string) {
	t.Helper()
	if code != 2 || out != "" || !strings.HasPrefix(errs, "fortik: Fortik unreachable or refused: blocking (fail closed): ") || strings.Count(errs, "\n") != 1 {
		t.Fatalf("%s: code=%d out=%q err=%q", name, code, out, errs)
	}
}

func TestClientFailsClosed(t *testing.T) {
	cases := map[string]struct {
		status int
		body   string
	}{
		"500":           {500, `{"decision":"allow"}`},
		"403":           {403, `{"error":"x"}`},
		"garbage":       {200, `not json`},
		"empty":         {200, `{}`},
		"odd decision":  {200, `{"decision":"maybe"}`},
		"redirect":      {302, ``},
		"decision type": {200, `{"decision":7}`},
	}
	for name, tc := range cases {
		srv := fakeGateway(t, tc.status, tc.body, nil)
		code, out, errs := run(t, strings.NewReader(sampleEvent), baseEnv(srv.URL))
		assertFailClosed(t, name, code, out, errs)
	}
}

func TestClientTimeout(t *testing.T) {
	old := clientTimeout
	clientTimeout = 200 * time.Millisecond
	defer func() { clientTimeout = old }()
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	}))
	defer srv.Close()
	defer close(done)
	code, out, errs := run(t, strings.NewReader(sampleEvent), baseEnv(srv.URL))
	assertFailClosed(t, "timeout", code, out, errs)
	if !strings.Contains(errs, "timeout") {
		t.Fatalf("cause: %q", errs)
	}
}

func TestClientDefaultTimeoutIs3s(t *testing.T) {
	if clientTimeout != 3*time.Second {
		t.Fatalf("client timeout %v", clientTimeout)
	}
}

func TestClientConnectionRefused(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	code, out, errs := run(t, strings.NewReader(sampleEvent), baseEnv("http://"+addr))
	assertFailClosed(t, "refused", code, out, errs)
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestClientInputAndConfigErrors(t *testing.T) {
	srv := fakeGateway(t, 200, `{"decision":"allow"}`, func(*http.Request) { t.Error("gateway must not be called") })
	big := `{"tool_input":{"content":"` + strings.Repeat("a", MaxBodyBytes) + `"}}`
	cases := map[string]struct {
		stdin io.Reader
		env   map[string]string
	}{
		"missing token":   {strings.NewReader(sampleEvent), map[string]string{"FORTIK_GATEWAY_URL": srv.URL}},
		"missing gateway": {strings.NewReader(sampleEvent), map[string]string{"FORTIK_AGENT_TOKEN": "x"}},
		"bad token file":  {strings.NewReader(sampleEvent), map[string]string{"FORTIK_GATEWAY_URL": srv.URL, "FORTIK_AGENT_TOKEN_FILE": "/nonexistent/x"}},
		"bad stdin json":  {strings.NewReader(`{not json`), baseEnv(srv.URL)},
		"stdin array":     {strings.NewReader(`[1,2]`), baseEnv(srv.URL)},
		"empty stdin":     {strings.NewReader(``), baseEnv(srv.URL)},
		"unreadable":      {errReader{}, baseEnv(srv.URL)},
		"nil stdin":       {nil, baseEnv(srv.URL)},
		"oversized stdin": {strings.NewReader(big), baseEnv(srv.URL)},
	}
	for name, tc := range cases {
		code, out, errs := run(t, tc.stdin, tc.env)
		assertFailClosed(t, name, code, out, errs)
	}
}

func TestClientTokenFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(f, []byte("tok-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := fakeGateway(t, 200, `{"decision":"allow"}`, func(r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok-file" {
			t.Errorf("auth %q", r.Header.Get("Authorization"))
		}
	})
	code, _, _ := run(t, strings.NewReader(sampleEvent), map[string]string{"FORTIK_GATEWAY_URL": srv.URL, "FORTIK_AGENT_TOKEN_FILE": f})
	if code != 0 {
		t.Fatalf("code %d", code)
	}
}
