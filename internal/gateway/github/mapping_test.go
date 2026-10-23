package github

import (
	"context"
	"errors"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"fortik/internal/action"
	"fortik/internal/authz"
	"fortik/internal/gateway"
)

var agent = authz.Principal{Kind: authz.KindAgent, Name: "coder_01", InstanceID: "i-1"}

func mapReq(t *testing.T, method, path, body string) (gateway.Op, *opState) {
	t.Helper()
	a := &Adapter{}
	r := httptest.NewRequest(method, "http://gw.local"+path, strings.NewReader(body))
	op, err := a.Map(context.Background(), agent, r, []byte(body))
	if err != nil {
		t.Fatalf("Map returned an error (must never): %v", err)
	}
	st := op.State.(*opState)
	if err := op.Action.Validate(); err != nil {
		t.Fatalf("mapped action does not validate: %v", err)
	}
	return op, st
}

func TestMapClassification(t *testing.T) {
	cases := []struct {
		name, method, path, body string
		verb                     action.Verb
		op, repo, branch         string
		paths                    []string
		perms                    map[string]string
		record                   string
	}{
		{"read repo", "GET", "/gw/github/repos/Acme/API", "", action.VerbRead, OpRead, "acme/api", "", nil, map[string]string{"metadata": "read"}, ""},
		{"read pulls", "GET", "/gw/github/repos/acme/api/pulls?state=open", "", action.VerbRead, OpRead, "acme/api", "", nil, map[string]string{"pull_requests": "read"}, ""},
		{"read contents head", "HEAD", "/gw/github/repos/acme/api/contents/a/b.go", "", action.VerbRead, OpRead, "acme/api", "", nil, map[string]string{"contents": "read"}, ""},
		{"read unknown subresource gets metadata only", "GET", "/gw/github/repos/acme/api/actions/secrets", "", action.VerbRead, OpRead, "acme/api", "", nil, map[string]string{"metadata": "read"}, ""},
		{"read outside repos", "GET", "/gw/github/user", "", action.VerbRead, OpRead, "", "", nil, map[string]string{}, ""},
		{"prefix already stripped", "GET", "/repos/acme/api", "", action.VerbRead, OpRead, "acme/api", "", nil, map[string]string{"metadata": "read"}, ""},
		{"create ref", "POST", "/gw/github/repos/acme/api/git/refs", `{"ref":"refs/heads/feat/x","sha":"aa"}`, action.VerbWrite, OpPush, "acme/api", "feat/x", nil, map[string]string{"contents": "write"}, recordRef},
		{"create tag ref", "POST", "/gw/github/repos/acme/api/git/refs", `{"ref":"refs/tags/v1","sha":"aa"}`, action.VerbWrite, OpPush, "acme/api", "refs/tags/v1", nil, map[string]string{"contents": "write"}, recordRef},
		{"update ref", "PATCH", "/gw/github/repos/acme/api/git/refs/heads/release/2.0", `{"sha":"bb"}`, action.VerbWrite, OpPush, "acme/api", "release/2.0", nil, map[string]string{"contents": "write"}, recordRef},
		{"force update ref", "PATCH", "/gw/github/repos/acme/api/git/refs/heads/main", `{"sha":"bb","force":true}`, action.VerbWrite, OpForcePush, "acme/api", "main", nil, map[string]string{"contents": "write"}, recordRef},
		{"force false", "PATCH", "/gw/github/repos/acme/api/git/refs/heads/main", `{"sha":"bb","force":false}`, action.VerbWrite, OpPush, "acme/api", "main", nil, map[string]string{"contents": "write"}, recordRef},
		{"delete branch", "DELETE", "/gw/github/repos/acme/api/git/refs/heads/feat/old", "", action.VerbDelete, OpDeleteBranch, "acme/api", "feat/old", nil, map[string]string{"contents": "write"}, recordRef},
		{"delete tag", "DELETE", "/gw/github/repos/acme/api/git/refs/tags/v1", "", action.VerbDelete, OpDeleteRelease, "acme/api", "refs/tags/v1", nil, map[string]string{"contents": "write"}, ""},
		{"contents put with branch", "PUT", "/gw/github/repos/acme/api/contents/src/a.go", `{"message":"m","content":"eA==","branch":"feat/y"}`, action.VerbWrite, OpPush, "acme/api", "feat/y", []string{"src/a.go"}, map[string]string{"contents": "write"}, recordRef},
		{"contents put default branch", "PUT", "/gw/github/repos/acme/api/contents/README.md", `{"message":"m","content":"eA=="}`, action.VerbWrite, OpPush, "acme/api", "", []string{"README.md"}, map[string]string{"contents": "write"}, recordRef},
		{"contents workflow", "PUT", "/gw/github/repos/acme/api/contents/.github/workflows/ci.yml", `{"message":"m","content":"eA==","branch":"x"}`, action.VerbWrite, OpPush, "acme/api", "x", []string{".github/workflows/ci.yml"}, map[string]string{"contents": "write", "workflows": "write"}, recordRef},
		{"contents delete", "DELETE", "/gw/github/repos/acme/api/contents/a.txt", `{"message":"m","sha":"cc","branch":"feat/z"}`, action.VerbWrite, OpPush, "acme/api", "feat/z", []string{"a.txt"}, map[string]string{"contents": "write"}, recordRef},
		{"create pr", "POST", "/gw/github/repos/acme/api/pulls", `{"title":"t","head":"feat/x","base":"main"}`, action.VerbWrite, OpCreatePR, "acme/api", "main", nil, map[string]string{"pull_requests": "write"}, ""},
		{"close pr", "PATCH", "/gw/github/repos/acme/api/pulls/7", `{"state":"closed"}`, action.VerbWrite, OpClosePR, "acme/api", "", nil, map[string]string{"pull_requests": "write"}, recordPR},
		{"merge pr", "PUT", "/gw/github/repos/acme/api/pulls/7/merge", `{"merge_method":"squash"}`, action.VerbWrite, OpMergePR, "acme/api", "", nil, map[string]string{"contents": "write", "pull_requests": "write"}, recordMerge},
		{"delete repo", "DELETE", "/gw/github/repos/acme/api", "", action.VerbDelete, OpDeleteRepo, "acme/api", "", nil, map[string]string{"administration": "write"}, ""},
		{"collaborator", "PUT", "/gw/github/repos/acme/api/collaborators/eve", `{"permission":"admin"}`, action.VerbGrant, OpCollaborator, "acme/api", "", nil, map[string]string{"administration": "write"}, ""},
		{"team grant", "PUT", "/gw/github/orgs/acme/teams/devs/repos/acme/api", `{"permission":"push"}`, action.VerbGrant, OpTeamRepoGrant, "acme/api", "", nil, map[string]string{"administration": "write"}, ""},
		{"protection put", "PUT", "/gw/github/repos/acme/api/branches/release/1/protection", `{}`, action.VerbGrant, OpBranchProtect, "acme/api", "release/1", nil, map[string]string{"administration": "write"}, ""},
		{"protection delete", "DELETE", "/gw/github/repos/acme/api/branches/main/protection", "", action.VerbGrant, OpBranchProtect, "acme/api", "main", nil, map[string]string{"administration": "write"}, ""},
		{"set secret", "PUT", "/gw/github/repos/acme/api/actions/secrets/TOKEN", `{"encrypted_value":"x","key_id":"1"}`, action.VerbWrite, OpSetSecret, "acme/api", "", nil, map[string]string{"secrets": "write"}, ""},
		{"webhook", "POST", "/gw/github/repos/acme/api/hooks", `{"config":{"url":"https://x"}}`, action.VerbWrite, OpCreateWebhook, "acme/api", "", nil, map[string]string{"repository_hooks": "write"}, ""},
		{"deploy key", "POST", "/gw/github/repos/acme/api/keys", `{"key":"ssh-ed25519 AAA"}`, action.VerbWrite, OpAddDeployKey, "acme/api", "", nil, map[string]string{"administration": "write"}, ""},
		{"dispatch", "POST", "/gw/github/repos/acme/api/actions/workflows/ci.yml/dispatches", `{"ref":"main"}`, action.VerbExecute, OpRunWorkflow, "acme/api", "main", nil, map[string]string{"actions": "write"}, ""},
		{"delete release", "DELETE", "/gw/github/repos/acme/api/releases/12", "", action.VerbDelete, OpDeleteRelease, "acme/api", "", nil, map[string]string{"contents": "write"}, ""},
		{"delete release asset", "DELETE", "/gw/github/repos/acme/api/releases/assets/12", "", action.VerbDelete, OpDeleteRelease, "acme/api", "", nil, map[string]string{"contents": "write"}, ""},
		{"issue comment", "POST", "/gw/github/repos/acme/api/issues/3/comments", `{"body":"hi"}`, action.VerbWrite, OpComment, "acme/api", "", nil, map[string]string{"issues": "write"}, ""},
		{"pr review comment", "POST", "/gw/github/repos/acme/api/pulls/3/comments", `{"body":"hi"}`, action.VerbWrite, OpComment, "acme/api", "", nil, map[string]string{"pull_requests": "write"}, ""},
		{"edit comment", "PATCH", "/gw/github/repos/acme/api/issues/comments/99", `{"body":"x"}`, action.VerbWrite, OpComment, "acme/api", "", nil, map[string]string{"issues": "write"}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			op, st := mapReq(t, c.method, c.path, c.body)
			a := op.Action
			if a.Verb != c.verb || st.operation != c.op || st.repo != c.repo || st.branch != c.branch || st.record != c.record {
				t.Fatalf("got verb=%s op=%s repo=%q branch=%q record=%q; want %s %s %q %q %q",
					a.Verb, st.operation, st.repo, st.branch, st.record, c.verb, c.op, c.repo, c.branch, c.record)
			}
			if st.unknown {
				t.Fatal("classified request marked unknown")
			}
			if !reflect.DeepEqual(st.perms, c.perms) {
				t.Fatalf("perms = %v, want %v", st.perms, c.perms)
			}
			if got, _ := a.Target["paths"].([]string); !reflect.DeepEqual(got, c.paths) {
				t.Fatalf("paths = %v, want %v", got, c.paths)
			}
			if a.System != "github" || a.Source != action.SourceAppGateway || a.AgentID != "coder_01" || a.InstanceID != "i-1" {
				t.Fatalf("identity fields wrong: %+v", a)
			}
			if a.Target["operation"] != c.op {
				t.Fatalf("target.operation = %v", a.Target["operation"])
			}
			if c.repo != "" && a.Target["repo"] != c.repo {
				t.Fatalf("target.repo = %v", a.Target["repo"])
			}
		})
	}
}

// Requests that must fail closed as UNKNOWN (POL-002 denies them).
func TestMapUnknownFailsClosed(t *testing.T) {
	cases := []struct{ name, method, path, body string }{
		{"graphql", "POST", "/gw/github/graphql", `{"query":"mutation{}"}`},
		{"unlisted endpoint", "POST", "/gw/github/repos/acme/api/labels", `{"name":"x"}`},
		{"edit pr title", "PATCH", "/gw/github/repos/acme/api/pulls/7", `{"title":"t"}`},
		{"close pr and change base", "PATCH", "/gw/github/repos/acme/api/pulls/7", `{"state":"closed","base":"main"}`},
		{"case-variant duplicate force", "PATCH", "/gw/github/repos/acme/api/git/refs/heads/main", `{"sha":"bb","force":true,"Force":false}`},
		{"exact duplicate key", "PATCH", "/gw/github/repos/acme/api/git/refs/heads/main", `{"sha":"bb","force":false,"force":true}`},
		{"force not boolean", "PATCH", "/gw/github/repos/acme/api/git/refs/heads/main", `{"sha":"bb","force":"true"}`},
		{"missing sha", "PATCH", "/gw/github/repos/acme/api/git/refs/heads/main", `{"force":true}`},
		{"body not object", "PATCH", "/gw/github/repos/acme/api/git/refs/heads/main", `["x"]`},
		{"trailing data", "PATCH", "/gw/github/repos/acme/api/git/refs/heads/main", `{"sha":"bb"} {"force":true}`},
		{"invalid json", "PATCH", "/gw/github/repos/acme/api/git/refs/heads/main", `{"sha":`},
		{"encoded slash", "DELETE", "/gw/github/repos/acme/api/git/refs/heads/feat%2Fx", ""},
		{"dot dot", "DELETE", "/gw/github/repos/acme/api/git/refs/heads/../../../x", ""},
		{"empty segment", "DELETE", "/gw/github/repos/acme//git/refs/heads/x", ""},
		{"bad owner", "DELETE", "/gw/github/repos/-bad-/api", ""},
		{"tag ref patch", "PATCH", "/gw/github/repos/acme/api/git/refs/tags/v1", `{"sha":"bb","force":true}`},
		{"invalid ref create", "POST", "/gw/github/repos/acme/api/git/refs", `{"ref":"heads/x","sha":"aa"}`},
		{"branch with ..", "PUT", "/gw/github/repos/acme/api/contents/a", `{"message":"m","content":"","branch":"a..b"}`},
		{"branch not string", "PUT", "/gw/github/repos/acme/api/contents/a", `{"message":"m","content":"","branch":1}`},
		{"mint token via gateway", "POST", "/gw/github/app/installations/777/access_tokens", `{}`},
		{"revoke via gateway", "DELETE", "/gw/github/installation/token", ""},
		{"options", "OPTIONS", "/gw/github/repos/acme/api", ""},
		{"pr number not canonical", "PUT", "/gw/github/repos/acme/api/pulls/07/merge", ""},
		{"wrong case route word", "PATCH", "/gw/github/repos/acme/api/GIT/refs/heads/main", `{"sha":"bb","force":true}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			op, st := mapReq(t, c.method, c.path, c.body)
			if op.Action.Verb != "UNKNOWN" || !st.unknown || op.Action.Target["operation"] != OpUnknown {
				t.Fatalf("want UNKNOWN, got verb=%s op=%v", op.Action.Verb, op.Action.Target["operation"])
			}
			if len(st.perms) != 0 || st.record != recordNone {
				t.Fatalf("unknown op must carry no permissions or record: %v %q", st.perms, st.record)
			}
		})
	}
}

func TestMapTargetHasNoPayload(t *testing.T) {
	op, _ := mapReq(t, "PUT", "/gw/github/repos/acme/api/contents/notes.txt",
		`{"message":"customer jane@example.com","content":"c2VjcmV0LWRhdGE=","branch":"feat/a"}`)
	b := strings.ToLower(strings.Join([]string{op.Action.Target["endpoint"].(string), op.Action.Target["operation"].(string)}, " "))
	for k, v := range op.Action.Target {
		if s, ok := v.(string); ok && (strings.Contains(s, "jane@") || strings.Contains(s, "c2VjcmV0")) {
			t.Fatalf("target.%s carries body content: %q", k, s)
		}
	}
	if !strings.Contains(b, "/contents/{path}") {
		t.Fatalf("endpoint not templated: %q", b)
	}
	if op.Action.PayloadSummary.Bytes == 0 {
		t.Fatal("payload summary bytes not set")
	}
}

func TestReducedForm(t *testing.T) {
	if rec, err := reducedForm(nil); err != nil || rec {
		t.Fatalf("empty: %v %v", rec, err)
	}
	if rec, err := reducedForm(map[string]any{"record_ref": true}); err != nil || !rec {
		t.Fatalf("record_ref: %v %v", rec, err)
	}
	for _, rf := range []map[string]any{
		{"record_ref": true, "delay_send_seconds": 120.0},
		{"narrow_share": true},
		{"record_ref": "true"},
	} {
		_, err := reducedForm(rf)
		var u gateway.ErrReducedFormUnsupported
		if !errors.As(err, &u) {
			t.Fatalf("%v: want ErrReducedFormUnsupported, got %v", rf, err)
		}
	}
}

func TestTemplHidesIdentifiers(t *testing.T) {
	if got := templ([]string{"pulls", "123", "comments"}); got != "/pulls/{…}/comments" {
		t.Fatalf("templ = %q", got)
	}
}
