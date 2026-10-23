package google

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/access"
	"fortik/internal/config"
	"fortik/internal/control"
	"fortik/internal/decide"
	"fortik/internal/diary"
	"fortik/internal/gateway"
	"fortik/internal/integrations"
	"fortik/internal/policy"
	"fortik/internal/secrets"
	"fortik/internal/testutil"
	"fortik/internal/undo"
)

const (
	mailAgent    = "mail_agent"
	mailToken    = "agt_mail_agent_token"
	noIDAgent    = "noid_agent"
	noIDToken    = "agt_noid_agent_token"
	agentMailbox = "agent@acme.test"
)

func policyDir() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..", "..", "policies")
}

// permissiveAccess grants the widest Gmail/Drive profiles so these tests
// exercise the Workspace rules (the access gate has its own tests).
type permissiveAccess struct{}

func (permissiveAccess) PolicyInput(_ context.Context, _ string, system string) (access.PolicyInput, error) {
	profiles := map[string]string{
		"gmail": `{"send":"any","read":true,"max_recipients":25}`,
		"drive": `{"mode":"read_write","share":"any"}`,
	}
	p, ok := profiles[system]
	if !ok {
		return access.PolicyInput{System: system, Profile: json.RawMessage("null")}, nil
	}
	return access.PolicyInput{System: system, Version: 1, Profile: json.RawMessage(p)}, nil
}

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *testClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type env struct {
	t       *testing.T
	pool    *pgxpool.Pool
	diary   *diary.Diary
	ctl     *control.Store
	google  *fakeGoogle
	src     *integrations.PGStore
	store   *secrets.EncFile
	rec     *recorder
	adapter *Adapter
	gw      *httptest.Server
	clock   *testClock
	undo    *undo.PGStore

	labelsMu sync.Mutex
	labels   []string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	pool, _ := testutil.FortikDB(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng, err := policy.NewEngine(ctx, policyDir(), log)
	if err != nil {
		t.Fatal(err)
	}
	d := diary.New(pool)
	ctl := control.NewStore(pool, d)
	for _, id := range []string{mailAgent, noIDAgent} {
		if _, err := ctl.Register(ctx, control.Agent{AgentID: id, Type: "test", Sponsor: "owner@acme.test"}, "test"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `UPDATE agents SET workspace_user = $2 WHERE agent_id = $1`, mailAgent, agentMailbox); err != nil {
		t.Fatal(err)
	}
	svc := &decide.Service{Pool: pool, Policy: eng, Control: ctl, Diary: d, Log: log, Access: permissiveAccess{}}

	// The real secret store (encfile) and integrations store (workstream A):
	// the integration is configured exactly as the console would.
	store, err := secrets.NewEncFile(t.TempDir(), bytes.Repeat([]byte{7}, secrets.MasterKeySize))
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, pool: pool, diary: d, ctl: ctl, google: newFakeGoogle(t), store: store, rec: &recorder{},
		clock: &testClock{t: time.Now().UTC()}, undo: undo.NewPGStore(pool, d)}
	e.src = integrations.NewPGStore(pool, d, store)
	sa := e.google.serviceAccountJSON()
	if _, err := e.src.Configure(ctx, IntegrationKey, integrations.ConfigureInput{
		Config: map[string]json.RawMessage{
			"primary_domain":   json.RawMessage(`"acme.test"`),
			"internal_domains": json.RawMessage(`["acme-corp.test"]`),
			"test_user":        json.RawMessage(`"` + agentMailbox + `"`),
		},
		Secrets: map[string]*string{"service_account_json": &sa},
	}, "user:security@acme.test"); err != nil {
		t.Fatal(err)
	}
	if err := e.store.Put(ctx, "agent_tokens", []byte(`{"`+mailAgent+`":"`+sha(mailToken)+`","`+noIDAgent+`":"`+sha(noIDToken)+`"}`)); err != nil {
		t.Fatal(err)
	}

	cfg := config.GatewayConfig{GoogleTokenURL: e.google.tokenURL(), GmailBaseURL: e.google.srv.URL,
		DriveBaseURL: e.google.srv.URL, DriveUploadURL: e.google.srv.URL, MaxBodyBytes: 25 << 20, DelayedSendPoll: 10 * time.Millisecond}
	e.adapter, err = New(Options{Config: cfg, Source: e.src, Directory: PGDirectory{Pool: pool}, Pool: pool, Diary: d,
		Secrets: e.store, Issuances: e.rec, Log: log, Now: e.clock.now,
		Labels: func(context.Context, string, *gateway.Op) ([]string, error) {
			e.labelsMu.Lock()
			defer e.labelsMu.Unlock()
			return append([]string(nil), e.labels...), nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := gateway.NewServer(cfg, svc, gateway.NewAgentAuth(e.store, "agent_tokens", log), []gateway.Adapter{e.adapter}, log, gateway.WithDiary(d))
	if err != nil {
		t.Fatal(err)
	}
	e.gw = httptest.NewServer(srv)
	t.Cleanup(e.gw.Close)
	return e
}

func (e *env) setLabels(l ...string) {
	e.labelsMu.Lock()
	defer e.labelsMu.Unlock()
	e.labels = l
}

type resp struct {
	code   int
	header http.Header
	body   []byte
}

func (r resp) json(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.body, &m); err != nil {
		t.Fatalf("response %d %q: %v", r.code, r.body, err)
	}
	return m
}

func (r resp) refusal(t *testing.T) map[string]any {
	t.Helper()
	e, _ := r.json(t)["error"].(map[string]any)
	if e == nil {
		t.Fatalf("no error object: %s", r.body)
	}
	return e
}

func (e *env) call(method, path, token string, body []byte, hdr map[string]string) resp {
	e.t.Helper()
	req, err := http.NewRequest(method, e.gw.URL+path, bytes.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return resp{code: res.StatusCode, header: res.Header, body: b}
}

func rfc822(to, subject string) []byte {
	return []byte("From: " + agentMailbox + "\r\nTo: " + to + "\r\nSubject: " + subject + "\r\nContent-Type: text/plain\r\n\r\nconfidential body text\r\n")
}

func sendBody(raw []byte) []byte {
	b, _ := json.Marshal(map[string]string{"raw": base64.RawURLEncoding.EncodeToString(raw)})
	return b
}

const sendPath = "/gw/google/gmail/v1/users/me/messages/send"

func (e *env) count(q string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.pool.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func (e *env) str(q string, args ...any) string {
	e.t.Helper()
	var s string
	if err := e.pool.QueryRow(context.Background(), q, args...).Scan(&s); err != nil {
		e.t.Fatal(err)
	}
	return s
}

func (e *env) decision(actionID string) (string, string) {
	e.t.Helper()
	var d, rule string
	if err := e.pool.QueryRow(context.Background(), `SELECT decision, rule_id FROM actions WHERE action_id = $1`, actionID).Scan(&d, &rule); err != nil {
		e.t.Fatalf("action %s: %v", actionID, err)
	}
	return d, rule
}

// diaryHasNo asserts no Diary entry contains s (message content, tokens...).
func (e *env) diaryHasNo(s string) {
	e.t.Helper()
	if n := e.count(`SELECT count(*) FROM diary WHERE strpos(body_json, $1) > 0`, s); n != 0 {
		e.t.Fatalf("Diary contains %q in %d entries", s, n)
	}
}

func (e *env) worker() *DelayedSender {
	w := e.adapter.NewDelayedSender()
	return w
}

// --- tests ---------------------------------------------------------------------

func TestInternalSendAllowedAndForwarded(t *testing.T) {
	e := newEnv(t)
	raw := rfc822("Bob <BOB@acme.test>, carol@acme-corp.test", "quarterly")
	r := e.call("POST", sendPath, mailToken, sendBody(raw), nil)
	if r.code != 200 {
		t.Fatalf("code %d: %s", r.code, r.body)
	}
	actionID := r.header.Get(gateway.ActionIDHeader)
	if d, rule := e.decision(actionID); d != "allow" {
		t.Fatalf("decision %s by %s", d, rule)
	}
	if id := r.json(t)["id"]; id != "msg-1" {
		t.Fatalf("gmail response not relayed: %s", r.body)
	}
	sent, _, _, _ := e.google.snapshot()
	if len(sent) != 1 || sent[0].Subject != agentMailbox || !bytes.Equal(sent[0].Raw, raw) {
		t.Fatalf("sent = %+v", sent)
	}
	var target struct {
		To              []string `json:"to"`
		ExternalDomains int      `json:"external_domains"`
	}
	if err := json.Unmarshal([]byte(e.str(`SELECT target::text FROM actions WHERE action_id = $1`, actionID)), &target); err != nil {
		t.Fatal(err)
	}
	if target.ExternalDomains != 0 || len(target.To) != 2 || target.To[0] != "bob@acme.test" {
		t.Fatalf("target = %+v", target)
	}
	// The issuance was recorded without the token.
	e.rec.mu.Lock()
	defer e.rec.mu.Unlock()
	if len(e.rec.creds) != 1 || e.rec.creds[0].ActionID != actionID || e.rec.creds[0].Secret != nil || e.rec.creds[0].System != "gmail" {
		t.Fatalf("issuances = %+v", e.rec.creds)
	}
	e.diaryHasNo("confidential body text")
	e.diaryHasNo("ya29.fake")
}

func TestExternalSendDelayedThenSentByWorker(t *testing.T) {
	e := newEnv(t)
	raw := rfc822("alice@external.test", "proposal")
	r := e.call("POST", sendPath, mailToken, sendBody(raw), nil)
	if r.code != 200 {
		t.Fatalf("code %d: %s", r.code, r.body)
	}
	actionID := r.header.Get(gateway.ActionIDHeader)
	if d, rule := e.decision(actionID); d != "allow_reduced" || rule != "POL-202" {
		t.Fatalf("decision %s by %s", d, rule)
	}
	m := r.json(t)
	fk, _ := m["fortik"].(map[string]any)
	if m["id"] != "fortik-delayed-"+actionID || fk["status"] != "delayed" || fk["action_id"] != actionID || fk["send_at"] == "" {
		t.Fatalf("delayed response = %s", r.body)
	}
	if sent, _, _, _ := e.google.snapshot(); len(sent) != 0 {
		t.Fatal("external message sent before the delay")
	}
	// Stored encrypted; handle prepared; key created in the secret store.
	var payload []byte
	if err := e.pool.QueryRow(context.Background(), `SELECT payload_enc FROM delayed_sends WHERE action_id = $1 AND status = 'pending'`, actionID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(payload, []byte("confidential")) || bytes.Contains(payload, []byte("alice@")) {
		t.Fatal("queued message is not encrypted")
	}
	if e.str(`SELECT status FROM undo_handles WHERE action_id = $1 AND kind = 'gmail_delayed_send'`, actionID) != "active" {
		t.Fatal("undo handle not active")
	}
	if k, err := e.store.Get(context.Background(), DelayedSendKeySecret); err != nil || len(k) == 0 {
		t.Fatalf("data key not created: %v", err)
	}
	if e.str(`SELECT meta_json::text FROM delayed_sends WHERE action_id = $1`, actionID) == "" {
		t.Fatal("no meta")
	}

	w := e.worker()
	if n, err := w.RunOnce(context.Background()); err != nil || n != 0 {
		t.Fatalf("not yet due: n=%d err=%v", n, err)
	}
	e.clock.add(121 * time.Second)
	if n, err := w.RunOnce(context.Background()); err != nil || n != 1 {
		t.Fatalf("due: n=%d err=%v", n, err)
	}
	sent, _, _, _ := e.google.snapshot()
	if len(sent) != 1 || !bytes.Equal(sent[0].Raw, raw) || sent[0].Subject != agentMailbox {
		t.Fatalf("sent = %+v", sent)
	}
	if s := e.str(`SELECT status FROM delayed_sends WHERE action_id = $1`, actionID); s != "sent" {
		t.Fatalf("status %s", s)
	}
	if s := e.str(`SELECT status || '|' || COALESCE(error, '') FROM undo_handles WHERE action_id = $1`, actionID); s != "used|sent: not undoable" {
		t.Fatalf("handle %s", s)
	}
	if e.count(`SELECT count(*) FROM diary WHERE event_type = $1 AND body_json LIKE '%' || $2 || '%'`, EventDelayedSent, actionID) != 1 {
		t.Fatal("no gmail.delayed_send.sent event")
	}
	// Undo after sending: 409-class "already sent".
	if _, err := e.adapter.UndoExecutor().Undo(context.Background(), undo.Handle{ActionID: actionID, Kind: KindGmailDelayedSend}); err == nil ||
		!errors.Is(err, undo.ErrNothingToUndo) || !strings.Contains(err.Error(), "already sent: NOT undoable") {
		t.Fatalf("undo after send: %v", err)
	}
	e.diaryHasNo("confidential body text")
}

func TestExternalSendWithSensitiveLabelsRefused(t *testing.T) {
	e := newEnv(t)
	e.setLabels("customer_pii")
	r := e.call("POST", sendPath, mailToken, sendBody(rfc822("alice@external.test", "export")), nil)
	if r.code != 403 {
		t.Fatalf("code %d: %s", r.code, r.body)
	}
	ref := r.refusal(t)
	if ref["code"] != "fortik_refused" || ref["rule_id"] != "POL-201" || ref["decision"] != "hold" || ref["held"] != true || ref["class"] != "red" {
		t.Fatalf("refusal = %v", ref)
	}
	if ref["action_id"] != r.header.Get(gateway.ActionIDHeader) {
		t.Fatal("action id header mismatch")
	}
	st, _ := e.ctl.Get(context.Background(), mailAgent)
	if st.Level != control.Isolated {
		t.Fatalf("agent level %s, want ISOLATED", st.Level)
	}
	if sent, _, reqs, _ := e.google.snapshot(); len(sent) != 0 || len(reqs) != 0 {
		t.Fatalf("refused send reached Google: %v", reqs)
	}
	if e.count(`SELECT count(*) FROM delayed_sends`) != 0 {
		t.Fatal("refused send queued")
	}
}

func TestDelayedSendCancelledViaUndo(t *testing.T) {
	e := newEnv(t)
	r := e.call("POST", sendPath, mailToken, sendBody(rfc822("alice@external.test", "oops")), nil)
	if r.code != 200 {
		t.Fatalf("code %d: %s", r.code, r.body)
	}
	actionID := r.header.Get(gateway.ActionIDHeader)
	ctx := context.Background()
	// The API's undo flow: claim, execute, complete.
	h, err := e.undo.Claim(ctx, actionID, "user:security@acme.test")
	if err != nil {
		t.Fatal(err)
	}
	res, err := e.adapter.UndoExecutor().Undo(ctx, h)
	if err != nil || res["cancelled"] != true {
		t.Fatalf("undo: %v %v", res, err)
	}
	if err := e.undo.Complete(ctx, actionID, "user:security@acme.test", res); err != nil {
		t.Fatal(err)
	}
	e.clock.add(10 * time.Minute)
	if _, err := e.worker().RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if sent, _, _, _ := e.google.snapshot(); len(sent) != 0 {
		t.Fatal("cancelled message was sent")
	}
	if s := e.str(`SELECT status FROM delayed_sends WHERE action_id = $1`, actionID); s != "cancelled" {
		t.Fatalf("status %s", s)
	}
	if s := e.str(`SELECT status FROM undo_handles WHERE action_id = $1`, actionID); s != "used" {
		t.Fatalf("handle %s", s)
	}
	// A second undo finds nothing to cancel.
	if _, err := e.adapter.UndoExecutor().Undo(ctx, h); !errors.Is(err, undo.ErrNothingToUndo) {
		t.Fatalf("second undo: %v", err)
	}
}

func TestWorkerCancelsWhenAgentSteppedDown(t *testing.T) {
	e := newEnv(t)
	r := e.call("POST", sendPath, mailToken, sendBody(rfc822("alice@external.test", "later")), nil)
	if r.code != 200 {
		t.Fatalf("code %d: %s", r.code, r.body)
	}
	actionID := r.header.Get(gateway.ActionIDHeader)
	ctx := context.Background()
	if _, err := e.ctl.SetLevel(ctx, mailAgent, control.ReadOnly, "suspicious", "user:security@acme.test"); err != nil {
		t.Fatal(err)
	}
	e.clock.add(5 * time.Minute)
	if n, err := e.worker().RunOnce(ctx); err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if sent, _, _, _ := e.google.snapshot(); len(sent) != 0 {
		t.Fatal("sent although the agent is READ_ONLY")
	}
	if s := e.str(`SELECT status FROM delayed_sends WHERE action_id = $1`, actionID); s != "cancelled" {
		t.Fatalf("status %s", s)
	}
	if s := e.str(`SELECT status FROM undo_handles WHERE action_id = $1`, actionID); s != "failed" {
		t.Fatalf("handle %s", s)
	}
	if e.count(`SELECT count(*) FROM diary WHERE event_type = $1 AND body_json LIKE '%READ_ONLY%'`, EventDelayedCancelled) != 1 {
		t.Fatal("no cancellation event")
	}
}

func TestWorkerRetriesTransientGmailErrors(t *testing.T) {
	e := newEnv(t)
	r := e.call("POST", sendPath, mailToken, sendBody(rfc822("alice@external.test", "retry")), nil)
	actionID := r.header.Get(gateway.ActionIDHeader)
	e.google.mu.Lock()
	e.google.sendStatus = 503
	e.google.mu.Unlock()
	ctx := context.Background()
	w := e.worker()
	e.clock.add(3 * time.Minute)
	if _, err := w.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if s := e.str(`SELECT status FROM delayed_sends WHERE action_id = $1`, actionID); s != "pending" {
		t.Fatalf("after a 503 the send must be retried, status %s", s)
	}
	e.google.mu.Lock()
	e.google.sendStatus = 0
	e.google.mu.Unlock()
	e.clock.add(5 * time.Minute)
	if _, err := w.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if s := e.str(`SELECT status FROM delayed_sends WHERE action_id = $1`, actionID); s != "sent" {
		t.Fatalf("status %s", s)
	}
}

func TestDriveAnyoneLinkNarrowedAndUndone(t *testing.T) {
	e := newEnv(t)
	body := []byte(`{"type":"anyone","role":"reader","allowFileDiscovery":true}`)
	r := e.call("POST", "/gw/google/drive/v3/files/file123/permissions?sendNotificationEmail=false&fields=role", mailToken, body,
		map[string]string{"Content-Type": "application/json"})
	if r.code != 200 {
		t.Fatalf("code %d: %s", r.code, r.body)
	}
	actionID := r.header.Get(gateway.ActionIDHeader)
	if d, rule := e.decision(actionID); d != "allow_reduced" || rule != "POL-211" {
		t.Fatalf("decision %s by %s", d, rule)
	}
	_, perms, _, _ := e.google.snapshot()
	if len(perms) != 1 {
		t.Fatalf("perms = %+v", perms)
	}
	p := perms["perm-1"]
	if p.FileID != "file123" || p.Body["type"] != "domain" || p.Body["domain"] != "acme.test" || p.Body["role"] != "reader" || len(p.Body) != 3 {
		t.Fatalf("share not narrowed: %+v", p.Body)
	}
	var hd struct {
		FileID       string `json:"file_id"`
		PermissionID string `json:"permission_id"`
	}
	if err := json.Unmarshal([]byte(e.str(`SELECT handle_json::text FROM undo_handles WHERE action_id = $1 AND kind = 'drive_permission' AND status = 'active'`, actionID)), &hd); err != nil {
		t.Fatal(err)
	}
	if hd.FileID != "file123" || hd.PermissionID != "perm-1" {
		t.Fatalf("handle = %+v", hd)
	}
	ctx := context.Background()
	h, err := e.undo.Claim(ctx, actionID, "user:security@acme.test")
	if err != nil {
		t.Fatal(err)
	}
	res, err := e.adapter.UndoExecutor().Undo(ctx, h)
	if err != nil || res["deleted_permission"] != "perm-1" {
		t.Fatalf("undo: %v %v", res, err)
	}
	if err := e.undo.Complete(ctx, actionID, "user:security@acme.test", res); err != nil {
		t.Fatal(err)
	}
	if _, perms, _, _ := e.google.snapshot(); len(perms) != 0 {
		t.Fatal("permission not deleted by undo")
	}
	if _, err := e.adapter.UndoExecutor().Undo(ctx, h); !errors.Is(err, undo.ErrNothingToUndo) {
		t.Fatalf("second undo: %v", err)
	}
}

func TestDriveInternalShareAllowedAsIs(t *testing.T) {
	e := newEnv(t)
	r := e.call("POST", "/gw/google/drive/v3/files/f9/permissions", mailToken,
		[]byte(`{"type":"user","role":"writer","emailAddress":"Dana@ACME.test"}`), nil)
	if r.code != 200 {
		t.Fatalf("code %d: %s", r.code, r.body)
	}
	if d, _ := e.decision(r.header.Get(gateway.ActionIDHeader)); d != "allow" {
		t.Fatalf("decision %s", d)
	}
	_, perms, _, _ := e.google.snapshot()
	if perms["perm-1"].Body["type"] != "user" || perms["perm-1"].Body["emailAddress"] != "Dana@ACME.test" {
		t.Fatalf("perm = %+v", perms)
	}
}

func TestDriveTrashIsDeleteAndHeld(t *testing.T) {
	e := newEnv(t)
	r := e.call("PATCH", "/gw/google/drive/v3/files/f1", mailToken, []byte(`{"trashed":true}`), nil)
	ref := r.refusal(t)
	if r.code != 403 || ref["rule_id"] != "POL-007" || ref["decision"] != "hold" {
		t.Fatalf("code %d %v", r.code, ref)
	}
	// Two spellings of one field are refused (Google accepts both).
	r = e.call("PATCH", "/gw/google/drive/v3/files/f1", mailToken, []byte(`{"trashed":false,"Trashed":true}`), nil)
	if ref := r.refusal(t); r.code != 403 || ref["rule_id"] != "POL-002" {
		t.Fatalf("duplicate field: %d %v", r.code, ref)
	}
}

func TestUnknownEndpointRefused(t *testing.T) {
	e := newEnv(t)
	for _, c := range []struct{ method, path string }{
		{"GET", "/gw/google/gmail/v1/users/me/threads"},
		{"POST", "/gw/google/upload/gmail/v1/users/me/messages/send?uploadType=resumable"},
		{"GET", "/gw/google/gmail/v1/users/me/messages/..%2F..%2Fsettings"},
		{"POST", "/gw/google/calendar/v3/calendars"},
	} {
		r := e.call(c.method, c.path, mailToken, []byte(`{}`), nil)
		ref := r.refusal(t)
		if r.code != 403 || ref["rule_id"] != "POL-002" || ref["decision"] != "deny" {
			t.Fatalf("%s %s: %d %v", c.method, c.path, r.code, ref)
		}
	}
	if _, _, reqs, _ := e.google.snapshot(); len(reqs) != 0 {
		t.Fatalf("unknown endpoints reached Google: %v", reqs)
	}
	st, _ := e.ctl.Get(context.Background(), mailAgent)
	if st.Level != control.Full {
		t.Fatalf("UNKNOWN must not step the agent down (level %s)", st.Level)
	}
}

func TestMissingIntegrationIs503AfterDecision(t *testing.T) {
	e := newEnv(t)
	if err := e.src.Delete(context.Background(), IntegrationKey, "user:security@acme.test"); err != nil {
		t.Fatal(err)
	}
	r := e.call("GET", "/gw/google/gmail/v1/users/me/messages", mailToken, nil, nil)
	if r.code != 503 {
		t.Fatalf("code %d: %s", r.code, r.body)
	}
	ref := r.refusal(t)
	if ref["code"] != "integration_not_configured" || ref["system"] != IntegrationKey {
		t.Fatalf("body = %s", r.body)
	}
	actionID := r.header.Get(gateway.ActionIDHeader)
	if d, _ := e.decision(actionID); d != "allow" {
		t.Fatalf("decision not recorded: %s", d)
	}
	if e.count(`SELECT count(*) FROM diary WHERE event_type = $1 AND body_json LIKE '%integration_not_configured%'`, gateway.EventNotExecuted) != 1 {
		t.Fatal("not_executed event missing")
	}
	// A send with no integration is classified fail-closed (all recipients external).
	r = e.call("POST", sendPath, mailToken, sendBody(rfc822("bob@acme.test", "x")), nil)
	if r.code != 503 {
		t.Fatalf("send code %d: %s", r.code, r.body)
	}
	if d, rule := e.decision(r.header.Get(gateway.ActionIDHeader)); d != "allow_reduced" || rule != "POL-202" {
		t.Fatalf("unconfigured send classified %s/%s", d, rule)
	}
	if e.count(`SELECT count(*) FROM delayed_sends`) != 0 {
		t.Fatal("queued without an integration")
	}
}

func TestBadTokenIs401(t *testing.T) {
	e := newEnv(t)
	for _, tok := range []string{"", "agt_not_a_real_token"} {
		if r := e.call("GET", "/gw/google/gmail/v1/users/me/messages", tok, nil, nil); r.code != 401 {
			t.Fatalf("token %q: %d", tok, r.code)
		}
	}
	if e.count(`SELECT count(*) FROM actions`) != 0 {
		t.Fatal("unauthenticated request was decided")
	}
}

func TestUserIDSpoofRefused(t *testing.T) {
	e := newEnv(t)
	r := e.call("GET", "/gw/google/gmail/v1/users/ceo@acme.test/messages", mailToken, nil, nil)
	if ref := r.refusal(t); r.code != 403 || ref["rule_id"] != "POL-002" {
		t.Fatalf("spoof: %d %v", r.code, ref)
	}
	// The agent's own mailbox address is accepted, and upstream cookies are not echoed.
	r = e.call("GET", "/gw/google/gmail/v1/users/"+agentMailbox+"/messages", mailToken, nil, nil)
	if r.code != 200 || r.header.Get("Set-Cookie") != "" {
		t.Fatalf("own mailbox: %d %v %s", r.code, r.header, r.body)
	}
	if _, _, reqs, _ := e.google.snapshot(); len(reqs) != 1 || !strings.Contains(reqs[0], agentMailbox) {
		t.Fatalf("requests = %v", reqs)
	}
}

func TestMissingWorkspaceUserRefused(t *testing.T) {
	e := newEnv(t)
	r := e.call("GET", "/gw/google/gmail/v1/users/me/messages", noIDToken, nil, nil)
	ref := r.refusal(t)
	if r.code != 403 || ref["rule_id"] != "GW-IDENTITY" || !strings.Contains(ref["reason"].(string), "workspace_user") {
		t.Fatalf("code %d %v", r.code, ref)
	}
	if _, _, reqs, mints := e.google.snapshot(); len(reqs) != 0 || mints != 0 {
		t.Fatal("contacted Google without an identity")
	}
}

func TestTokensCachedPerScopeSet(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 3; i++ {
		if r := e.call("GET", "/gw/google/gmail/v1/users/me/messages", mailToken, nil, nil); r.code != 200 {
			t.Fatalf("code %d", r.code)
		}
	}
	if _, _, _, mints := e.google.snapshot(); mints != 1 {
		t.Fatalf("mints = %d, want 1 (cached)", mints)
	}
	if r := e.call("GET", "/gw/google/drive/v3/files", mailToken, nil, nil); r.code != 200 {
		t.Fatalf("drive code %d", r.code)
	}
	if _, _, _, mints := e.google.snapshot(); mints != 2 {
		t.Fatalf("mints = %d, want 2 (new scope set)", mints)
	}
	// broker.RevokeAll path: dropping Drive keeps the Gmail token cached.
	ba := e.adapter.BrokerAdapters()
	if ba["drive"].System() != "drive" || ba["gmail"].System() != "gmail" {
		t.Fatal("broker adapters must be keyed by the issuance systems")
	}
	if msg, err := ba["drive"].RevokeAgent(context.Background(), mailAgent); err != nil || !strings.Contains(msg, "(1)") {
		t.Fatalf("drive revoke: %s %v", msg, err)
	}
	e.call("GET", "/gw/google/gmail/v1/users/me/messages", mailToken, nil, nil)
	if _, _, _, mints := e.google.snapshot(); mints != 2 {
		t.Fatalf("mints = %d after drive revoke, want 2 (gmail still cached)", mints)
	}
	if msg, _ := e.adapter.RevokeAgent(context.Background(), mailAgent); !strings.Contains(msg, "(1)") {
		t.Fatalf("revoke: %s", msg)
	}
	e.call("GET", "/gw/google/gmail/v1/users/me/messages", mailToken, nil, nil)
	if _, _, _, mints := e.google.snapshot(); mints != 3 {
		t.Fatalf("mints = %d after revoke, want 3", mints)
	}
}

func TestDraftSendUsesFetchedContent(t *testing.T) {
	e := newEnv(t)
	raw := rfc822("bob@acme.test", "draft")
	e.google.mu.Lock()
	e.google.drafts["d1"] = raw
	e.google.mu.Unlock()
	r := e.call("POST", "/gw/google/gmail/v1/users/me/drafts/send", mailToken, []byte(`{"id":"d1"}`), nil)
	if r.code != 200 {
		t.Fatalf("code %d: %s", r.code, r.body)
	}
	sent, _, _, _ := e.google.snapshot()
	if len(sent) != 1 || !bytes.Equal(sent[0].Raw, raw) || sent[0].ThreadID != "thr1" {
		t.Fatalf("sent = %+v", sent)
	}
	e.google.mu.Lock()
	deleted := append([]string(nil), e.google.deleted...)
	e.google.mu.Unlock()
	if len(deleted) != 1 || deleted[0] != "d1" {
		t.Fatalf("draft not deleted after send: %v", deleted)
	}
	// An external draft is delayed like any external send.
	e.google.mu.Lock()
	e.google.drafts["d2"] = rfc822("x@external.test", "draft2")
	e.google.mu.Unlock()
	r = e.call("POST", "/gw/google/gmail/v1/users/me/drafts/send", mailToken, []byte(`{"id":"d2"}`), nil)
	if r.code != 200 || r.json(t)["fortik"] == nil {
		t.Fatalf("external draft: %d %s", r.code, r.body)
	}
}

func TestForwardingSettingsAreGrantAndHeld(t *testing.T) {
	e := newEnv(t)
	r := e.call("POST", "/gw/google/gmail/v1/users/me/settings/filters", mailToken,
		[]byte(`{"criteria":{"from":"bank@x.test"},"action":{"forward":"me@evil.test"}}`), nil)
	if ref := r.refusal(t); r.code != 403 || ref["rule_id"] != "POL-001" {
		t.Fatalf("filter forward: %d %v", r.code, ref)
	}
	if _, _, reqs, _ := e.google.snapshot(); len(reqs) != 0 {
		t.Fatal("GRANT reached Google")
	}
}

func TestMultipartUploadSend(t *testing.T) {
	e := newEnv(t)
	raw := rfc822("bob@acme.test", "upload")
	body, ct, err := buildRelated([]byte(`{"threadId":"t-77"}`), "message/rfc822", raw)
	if err != nil {
		t.Fatal(err)
	}
	r := e.call("POST", "/gw/google/upload/gmail/v1/users/me/messages/send?uploadType=multipart", mailToken, body, map[string]string{"Content-Type": ct})
	if r.code != 200 {
		t.Fatalf("code %d: %s", r.code, r.body)
	}
	sent, _, _, _ := e.google.snapshot()
	if len(sent) != 1 || sent[0].ThreadID != "t-77" || !bytes.Equal(sent[0].Raw, raw) {
		t.Fatalf("sent = %+v", sent)
	}
}

func TestTester(t *testing.T) {
	e := newEnv(t)
	tester := NewTester(config.GatewayConfig{GoogleTokenURL: e.google.tokenURL(), GmailBaseURL: e.google.srv.URL}, nil)
	r, err := e.src.Get(context.Background(), IntegrationKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := tester.Test(context.Background(), r); err != nil {
		t.Fatalf("tester: %v", err)
	}
	e.google.mu.Lock()
	e.google.denySubject[agentMailbox] = true
	e.google.mu.Unlock()
	err = tester.Test(context.Background(), r)
	if err == nil || !strings.Contains(err.Error(), "unauthorized_client") || strings.Contains(err.Error(), "PRIVATE KEY") {
		t.Fatalf("tester failure: %v", err)
	}
	bad := r
	bad.Secrets = map[string]string{}
	if err := tester.Test(context.Background(), bad); !errors.Is(err, integrations.ErrNotConfigured) {
		t.Fatalf("missing secret: %v", err)
	}
}

func sha(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// A send that outlives StuckAfter is swept as outcome-unknown by another
// worker; when it then succeeds, the swept final state must not be rewritten
// to "sent" with a second, contradictory event.
func TestSweptInFlightSendNotRewrittenToSent(t *testing.T) {
	e := newEnv(t)
	r := e.call("POST", sendPath, mailToken, sendBody(rfc822("alice@external.test", "slow")), nil)
	if r.code != 200 {
		t.Fatalf("code %d: %s", r.code, r.body)
	}
	actionID := r.header.Get(gateway.ActionIDHeader)
	ctx := context.Background()
	w := e.worker()
	e.clock.add(3 * time.Minute)
	claimed, _, err := w.claim(ctx)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim: %d %v", len(claimed), err)
	}
	e.clock.add(w.StuckAfter + time.Minute)
	if err := e.worker().sweepStuck(ctx); err != nil {
		t.Fatal(err)
	}
	w.send(ctx, claimed[0]) // the slow send finally succeeds
	if s := e.str(`SELECT status FROM delayed_sends WHERE action_id = $1`, actionID); s != "failed" {
		t.Fatalf("swept row rewritten to %s", s)
	}
	if n := e.count(`SELECT count(*) FROM diary WHERE event_type = $1 AND body_json LIKE '%' || $2 || '%'`, EventDelayedSent, actionID); n != 0 {
		t.Fatalf("%d contradictory sent events", n)
	}
	if n := e.count(`SELECT count(*) FROM diary WHERE event_type = $1 AND body_json LIKE '%' || $2 || '%'`, EventDelayedLate, actionID); n != 1 {
		t.Fatalf("late outcome events = %d", n)
	}
}
