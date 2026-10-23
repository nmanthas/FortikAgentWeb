package google

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"fortik/internal/action"
	"fortik/internal/authz"
	"fortik/internal/decide"
	"fortik/internal/gateway"
	"fortik/internal/policy"
)

// staticDirectory is an AgentDirectory with fixed workspace users.
type staticDirectory map[string]string

func (d staticDirectory) WorkspaceUser(_ context.Context, agentID string) (string, error) {
	return d[agentID], nil
}

func mapAdapter() *Adapter {
	return &Adapter{
		dir:       staticDirectory{"a1": "agent@acme.test"},
		log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		gmailBase: "https://gmail.example", driveBase: "https://drive.example", driveUpload: "https://upload.example",
	}
}

func mapReq(t *testing.T, method, path, contentType string, body []byte) gateway.Op {
	t.Helper()
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	op, err := mapAdapter().Map(context.Background(), authz.Principal{Kind: authz.KindAgent, Name: "a1"}, r, body)
	if err != nil {
		t.Fatalf("Map must never fail: %v", err)
	}
	return op
}

func TestMapClassification(t *testing.T) {
	const g, d = "/gw/google/gmail/v1/users/", "/gw/google/drive/v3/files"
	cases := []struct {
		name, method, path, body string
		system                   string
		verb                     action.Verb
		target                   map[string]any // subset checked
	}{
		{"messages.list", "GET", g + "me/messages?q=from:x", "", "gmail", action.VerbRead, nil},
		{"messages.get", "GET", g + "me/messages/m1?format=full", "", "gmail", action.VerbRead, map[string]any{"message_id": "m1"}},
		{"getProfile", "GET", g + "me/profile", "", "gmail", action.VerbRead, nil},
		{"labels.list", "GET", g + "me/labels", "", "gmail", action.VerbRead, nil},
		{"own mailbox address", "GET", g + "agent@acme.test/labels", "", "gmail", action.VerbRead, nil},
		{"spoofed userId", "GET", g + "ceo@acme.test/labels", "", "gmail", "UNKNOWN", nil},
		{"trash", "POST", g + "me/messages/m1/trash", "", "gmail", action.VerbDelete, map[string]any{"count": 1}},
		{"delete", "DELETE", g + "me/messages/m1", "", "gmail", action.VerbDelete, nil},
		{"batchDelete", "POST", g + "me/messages/batchDelete", `{"ids":["a","b","c"]}`, "gmail", action.VerbDelete, map[string]any{"count": 3}},
		{"batchDelete extra field", "POST", g + "me/messages/batchDelete", `{"ids":["a"],"x":1}`, "gmail", "UNKNOWN", nil},
		{"forwarding address", "POST", g + "me/settings/forwardingAddresses", `{"forwardingEmail":"Out@Evil.test"}`, "gmail", action.VerbGrant,
			map[string]any{"forward_to": "out@evil.test"}},
		{"sendAs", "POST", g + "me/settings/sendAs", `{"sendAsEmail":"boss@acme.test"}`, "gmail", action.VerbGrant, nil},
		{"filter with forward", "POST", g + "me/settings/filters", `{"criteria":{},"action":{"forward":"x@evil.test"}}`, "gmail", action.VerbGrant,
			map[string]any{"operation": "filter_forward"}},
		{"filter without forward", "POST", g + "me/settings/filters", `{"criteria":{},"action":{"addLabelIds":["L"]}}`, "gmail", "UNKNOWN", nil},
		{"threads (unsupported)", "GET", g + "me/threads", "", "gmail", "UNKNOWN", nil},
		{"wrong method", "PUT", g + "me/messages", "", "gmail", "UNKNOWN", nil},
		{"access_token stripped, still READ", "GET", g + "me/messages?access_token=abc", "", "gmail", action.VerbRead, nil},
		{"calendar (unsupported API)", "GET", "/gw/google/calendar/v3/calendars", "", "google", "UNKNOWN", nil},
		{"traversal segment", "GET", g + "me/messages/%2E%2E", "", "google", "UNKNOWN", nil},

		{"files.list", "GET", d + "?q=x", "", "drive", action.VerbRead, nil},
		{"files.get media", "GET", d + "/f1?alt=media", "", "drive", action.VerbRead, map[string]any{"file_id": "f1", "alt": "media"}},
		{"files.export", "GET", d + "/f1/export?mimeType=text/plain", "", "drive", action.VerbRead, nil},
		{"files.create", "POST", d, `{"name":"x"}`, "drive", action.VerbWrite, nil},
		{"files.create upload", "POST", "/gw/google/upload/drive/v3/files?uploadType=media", "data", "drive", action.VerbWrite, nil},
		{"resumable upload refused", "POST", "/gw/google/upload/drive/v3/files?uploadType=resumable", "", "google", "UNKNOWN", nil},
		{"files.copy", "POST", d + "/f1/copy", `{}`, "drive", action.VerbWrite, nil},
		{"files.update", "PATCH", d + "/f1", `{"name":"y"}`, "drive", action.VerbWrite, nil},
		{"files.update trash", "PATCH", d + "/f1", `{"trashed":true}`, "drive", action.VerbDelete, map[string]any{"operation": "trash"}},
		{"files.update snake_case trash", "PATCH", d + "/f1", `{"trashed":false,"Trashed":true}`, "drive", "UNKNOWN", nil},
		{"files.update addParents", "PATCH", d + "/f1?addParents=shared1&removeParents=p0", `{}`, "drive", "UNKNOWN", nil},
		{"files.update add_parents spelling", "PATCH", d + "/f1?add_parents=shared1", `{}`, "drive", "UNKNOWN", nil},
		{"files.update removeParents only", "PATCH", d + "/f1?removeParents=p0", `{}`, "drive", action.VerbWrite, nil},
		{"files.update parents body", "PATCH", d + "/f1", `{"parents":["shared1"]}`, "drive", "UNKNOWN", nil},
		{"files.copy with parents", "POST", d + "/f1/copy", `{"parents":["shared1"]}`, "drive", "UNKNOWN", nil},
		{"files.create with parents", "POST", d, `{"name":"x","parents":["shared1"]}`, "drive", "UNKNOWN", nil},
		{"files.create media with addParents", "POST", "/gw/google/upload/drive/v3/files?uploadType=media&addParents=s", "data", "drive", "UNKNOWN", nil},
		{"files.delete", "DELETE", d + "/f1", "", "drive", action.VerbDelete, nil},
		{"emptyTrash", "DELETE", d + "/trash", "", "drive", action.VerbDelete, map[string]any{"operation": "empty_trash"}},
		{"share anyone", "POST", d + "/f1/permissions", `{"type":"anyone","role":"reader"}`, "drive", action.VerbExport,
			map[string]any{"operation": "share", "share_type": "anyone", "external": true, "file_id": "f1"}},
		{"share user (unclassified domain before Enrich)", "POST", d + "/f1/permissions", `{"type":"user","role":"writer","emailAddress":"a@acme.test"}`,
			"drive", action.VerbExport, map[string]any{"share_type": "user", "grantee": "a@acme.test", "external": true}},
		{"share ownership", "POST", d + "/f1/permissions?transferOwnership=true", `{"type":"user","role":"owner","emailAddress":"a@acme.test"}`,
			"drive", action.VerbGrant, map[string]any{"operation": "transfer_ownership"}},
		{"share unknown field", "POST", d + "/f1/permissions", `{"type":"anyone","role":"reader","inheritedFrom":"x"}`, "drive", "UNKNOWN", nil},
		{"share bad type", "POST", d + "/f1/permissions", `{"type":"world","role":"reader"}`, "drive", "UNKNOWN", nil},
		{"permissions.update", "PATCH", d + "/f1/permissions/p1", `{"role":"writer"}`, "drive", action.VerbExport,
			map[string]any{"permission_id": "p1"}},
		{"permissions.delete", "DELETE", d + "/f1/permissions/p1", "", "drive", action.VerbWrite, map[string]any{"permission_id": "p1"}},
		{"drive about (unsupported)", "GET", "/gw/google/drive/v3/about", "", "google", "UNKNOWN", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			op := mapReq(t, c.method, c.path, "application/json", []byte(c.body))
			if op.Action.Verb != c.verb || op.Action.System != c.system {
				t.Fatalf("got %s/%s (target %v), want %s/%s", op.Action.System, op.Action.Verb, op.Action.Target, c.system, c.verb)
			}
			for k, v := range c.target {
				if op.Action.Target[k] != v {
					t.Fatalf("target[%s] = %v, want %v (target %v)", k, op.Action.Target[k], v, op.Action.Target)
				}
			}
			if st, ok := op.State.(*opState); ok && !st.unknown && st.query.Has("access_token") {
				t.Fatal("agent-supplied access_token not stripped")
			}
		})
	}
}

const mixedMessage = "From: agent@acme.test\r\n" +
	"To: Bob <BOB@acme.test>, x@partner.test\r\n" +
	"To: y@partner.test\r\n" +
	"Cc: z@other.test, bob@acme.test\r\n" +
	"Bcc: hidden@acme-corp.test\r\n" +
	"Subject: report\r\n" +
	"MIME-Version: 1.0\r\n" +
	"Content-Type: multipart/mixed; boundary=b1\r\n\r\n" +
	"--b1\r\nContent-Type: text/plain\r\n\r\nsecret body\r\n" +
	"--b1\r\nContent-Type: application/pdf; name=a.pdf\r\nContent-Disposition: attachment; filename=a.pdf\r\nContent-Transfer-Encoding: base64\r\n\r\nAAAAAAAA\r\n" +
	"--b1\r\nContent-Type: text/csv\r\nContent-Disposition: attachment; filename=b.csv\r\n\r\n1,2,3\r\n" +
	"--b1--\r\n"

func TestMapSendSummary(t *testing.T) {
	body := []byte(`{"raw":"` + base64.RawURLEncoding.EncodeToString([]byte(mixedMessage)) + `"}`)
	op := mapReq(t, "POST", "/gw/google/gmail/v1/users/me/messages/send", "application/json", body)
	if op.Action.Verb != action.VerbSend {
		t.Fatalf("verb %s: %v", op.Action.Verb, op.Action.Target)
	}
	// Distinct recipients: bob, x, y, z, hidden (bob repeated in Cc).
	if ps := op.Action.PayloadSummary; ps.Recipients != 5 || ps.Attachments != 2 {
		t.Fatalf("summary = %+v", ps)
	}
	to, _ := op.Action.Target["to"].([]string)
	if len(to) != 3 || to[0] != "bob@acme.test" {
		t.Fatalf("to = %v", to)
	}
	if op.Action.Target["attachment_bytes"] != int64(6+5) {
		t.Fatalf("attachment bytes = %v", op.Action.Target["attachment_bytes"])
	}
	// Before Enrich no domain is known internal (fail closed): 4 distinct domains.
	if op.Action.Target["external_domains"] != 4 {
		t.Fatalf("unenriched external_domains = %v", op.Action.Target["external_domains"])
	}
	s := settings{primaryDomain: "acme.test", internal: map[string]bool{"acme.test": true, "acme-corp.test": true}}
	st := op.State.(*opState)
	mapAdapter().classifySend(&op, st, s, true)
	if op.Action.Target["external_domains"] != 2 {
		t.Fatalf("external_domains = %v, want 2 (partner.test, other.test)", op.Action.Target["external_domains"])
	}
	if strings.Contains(stringify(op.Action), "secret body") {
		t.Fatal("message body leaked into the action")
	}
}

func TestMapSendRejectsUnclassifiable(t *testing.T) {
	for name, body := range map[string]string{
		"unknown field":     `{"raw":"` + base64.RawURLEncoding.EncodeToString([]byte(mixedMessage)) + `","payload":{}}`,
		"not base64":        `{"raw":"!!!"}`,
		"duplicate raw":     `{"raw":"QQ","Raw":"QQ"}`,
		"address no domain": `{"raw":"` + base64.RawURLEncoding.EncodeToString([]byte("To: bob\r\n\r\nx")) + `"}`,
		"trailing json":     `{"raw":"QQ"} {}`,
	} {
		op := mapReq(t, "POST", "/gw/google/gmail/v1/users/me/messages/send", "application/json", []byte(body))
		if op.Action.Verb != "UNKNOWN" {
			t.Fatalf("%s: verb %s", name, op.Action.Verb)
		}
	}
}

func stringify(a action.Action) string {
	var b strings.Builder
	for k, v := range a.Target {
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(toString(v), "\n", " "), "\r", "")))
		b.WriteString(";")
	}
	return b.String()
}

func toString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []string:
		return strings.Join(t, ",")
	}
	return ""
}

func TestReducedPlan(t *testing.T) {
	send := &opState{send: &sendState{}}
	share := &opState{share: &shareState{create: true}}
	update := &opState{share: &shareState{create: false}}
	out := func(rf map[string]any) decide.Outcome {
		return decide.Outcome{Result: policy.Result{Decision: policy.AllowReduced, ReducedForm: rf}}
	}
	ok := []struct {
		st *opState
		rf map[string]any
	}{
		{send, map[string]any{"delay_send_seconds": float64(120)}},
		{share, map[string]any{"narrow_share": "domain", "record_permission": true}},
	}
	for _, c := range ok {
		if _, err := reducedPlan(c.st, out(c.rf)); err != nil {
			t.Fatalf("%v: %v", c.rf, err)
		}
	}
	bad := []struct {
		st  *opState
		rf  map[string]any
		key string
	}{
		{send, map[string]any{"delay_send_seconds": float64(120), "snapshot_rows": true}, "snapshot_rows"},
		{send, map[string]any{"narrow_share": "domain"}, "narrow_share"},
		{send, map[string]any{"delay_send_seconds": "soon"}, "delay_send_seconds"},
		{send, map[string]any{"delay_send_seconds": float64(-1)}, "delay_send_seconds"},
		{share, map[string]any{"delay_send_seconds": float64(60)}, "delay_send_seconds"},
		{share, map[string]any{"narrow_share": "user"}, "narrow_share"},
		{update, map[string]any{"narrow_share": "domain"}, "narrow_share"},
		{share, map[string]any{"record_ref": true}, "record_ref"},
		{share, map[string]any{}, "(empty reduced form)"},
	}
	for _, c := range bad {
		_, err := reducedPlan(c.st, out(c.rf))
		var u gateway.ErrReducedFormUnsupported
		if !errors.As(err, &u) || u.Key != c.key {
			t.Fatalf("%v: err %v, want unsupported %s", c.rf, err, c.key)
		}
	}
}

func TestNarrowedShareBody(t *testing.T) {
	sh := &shareState{role: "commenter", fields: map[string]any{"type": "anyone", "role": "commenter", "allowFileDiscovery": true}}
	b, err := sh.body(true, "acme.test")
	if err != nil || string(b) != `{"domain":"acme.test","role":"commenter","type":"domain"}` {
		t.Fatalf("narrowed body %s %v", b, err)
	}
	if _, err := sh.body(true, ""); err == nil {
		t.Fatal("narrowing without a primary domain must fail closed")
	}
}
