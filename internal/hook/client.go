package hook

// Client side of the Claude Code hook: `fortik hook claude-code`.
//
// Claude Code treats exit 2 as "block" and EVERY other outcome (another exit
// code, a crash, a timeout) as "proceed". The client therefore exits 2 on any
// problem at all: Fortik fails closed.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"fortik/internal/delegation"
)

// ClientPath is the gateway path the client posts to.
const ClientPath = "/v1/hook/claude-code"

// clientTimeout bounds the whole request (tests shorten it).
var clientTimeout = 3 * time.Second

// Exit codes Claude Code understands.
const (
	ExitAllow = 0 // no decision: Claude Code's permission flow continues
	ExitBlock = 2 // block; stderr is shown to Claude
)

// RunClaudeCode reads one PreToolUse event from stdin, asks Fortik and
// returns the process exit code. It never writes to stdout except the
// allow_reduced systemMessage JSON.
func RunClaudeCode(stdin io.Reader, stdout, stderr io.Writer, env func(string) string) (code int) {
	defer func() {
		if r := recover(); r != nil {
			failClosed(stderr, "internal error")
			code = ExitBlock
		}
	}()
	if env == nil {
		env = os.Getenv
	}
	resp, err := askFortik(stdin, env)
	if err != nil {
		failClosed(stderr, err.Error())
		return ExitBlock
	}
	switch resp.Decision {
	case "allow":
		return ExitAllow
	case "allow_reduced":
		msg := map[string]string{"systemMessage": oneLine(fmt.Sprintf("fortik: allowed in reduced form %s by %s: %s action_id=%s",
			reducedText(resp.ReducedForm), resp.RuleID, resp.Reason, resp.ActionID))}
		b, _ := json.Marshal(msg)
		_, _ = stdout.Write(append(b, '\n'))
		return ExitAllow
	case "hold", "deny":
		fmt.Fprintln(stderr, oneLine(fmt.Sprintf("fortik: %s (%s) by %s: %s action_id=%s", resp.Decision, resp.Class, resp.RuleID, resp.Reason, resp.ActionID)))
		return ExitBlock
	}
	failClosed(stderr, "unexpected decision "+fmt.Sprintf("%q", resp.Decision))
	return ExitBlock
}

func failClosed(stderr io.Writer, cause string) {
	fmt.Fprintln(stderr, oneLine("fortik: Fortik unreachable or refused: blocking (fail closed): "+cause))
}

func oneLine(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r < 0x20 {
			return ' '
		}
		return r
	}, s)
	if len(s) > 1000 {
		s = s[:1000]
	}
	return s
}

func reducedText(m map[string]any) string {
	if len(m) == 0 {
		return "{}"
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func askFortik(stdin io.Reader, env func(string) string) (*Response, error) {
	if stdin == nil {
		return nil, errors.New("no stdin")
	}
	raw, err := io.ReadAll(io.LimitReader(stdin, MaxBodyBytes+1))
	if err != nil {
		return nil, errors.New("stdin unreadable")
	}
	if len(raw) > MaxBodyBytes {
		return nil, errors.New("hook input larger than 1 MiB")
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, errors.New("hook input is not a JSON object")
	}
	gw := strings.TrimRight(strings.TrimSpace(env("FORTIK_GATEWAY_URL")), "/")
	if gw == "" {
		return nil, errors.New("FORTIK_GATEWAY_URL is not set")
	}
	token := strings.TrimSpace(env("FORTIK_AGENT_TOKEN"))
	if token == "" {
		if f := env("FORTIK_AGENT_TOKEN_FILE"); f != "" {
			b, err := os.ReadFile(f)
			if err != nil {
				return nil, errors.New("FORTIK_AGENT_TOKEN_FILE unreadable")
			}
			token = strings.TrimSpace(string(b))
		}
	}
	if token == "" {
		return nil, errors.New("no agent token (FORTIK_AGENT_TOKEN or FORTIK_AGENT_TOKEN_FILE)")
	}
	hints := map[string]string{}
	for _, k := range []string{"PGHOST", "PGPORT", "PGDATABASE", "PGHOSTADDR", "PGSERVICE", "PGSERVICEFILE", "HOME", "CLAUDE_PROJECT_DIR"} {
		if v := env(k); v != "" {
			hints[k] = v
		}
	}
	body, err := json.Marshal(map[string]any{"event": json.RawMessage(raw), "env": hints})
	if err != nil {
		return nil, errors.New("cannot encode request")
	}
	req, err := http.NewRequest(http.MethodPost, gw+ClientPath, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("bad FORTIK_GATEWAY_URL")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	if v := strings.TrimSpace(env("FORTIK_INSTANCE_ID")); v != "" {
		req.Header.Set("X-Fortik-Instance-Id", v)
	}
	if v := strings.TrimSpace(env("FORTIK_DELEGATION")); v != "" {
		req.Header.Set(delegation.Header, v)
	}
	cl := &http.Client{Timeout: clientTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := cl.Do(req)
	if err != nil {
		var te interface{ Timeout() bool }
		if errors.As(err, &te) && te.Timeout() {
			return nil, errors.New("timeout")
		}
		return nil, errors.New("connection failed")
	}
	defer res.Body.Close()
	rb, err := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	if err != nil {
		return nil, errors.New("response unreadable")
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, fmt.Errorf("gateway returned HTTP %d", res.StatusCode)
	}
	var out Response
	if err := json.Unmarshal(rb, &out); err != nil || out.Decision == "" {
		return nil, errors.New("malformed response")
	}
	return &out, nil
}
