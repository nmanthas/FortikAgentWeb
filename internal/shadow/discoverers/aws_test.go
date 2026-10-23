package discoverers_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"fortik/internal/broker/pgroles/pgrolestest"
	"fortik/internal/integrations"
	"fortik/internal/shadow"
	"fortik/internal/shadow/discoverers"
)

// fakeIAM is a LOCAL FAKE of the IAM query API subset shadow discovery uses
// (ListUsers, ListAccessKeys, GetAccessKeyLastUsed, UpdateAccessKey). It
// answers with the XML shapes the SDK parses. It is not AWS.
type fakeIAM struct {
	srv *httptest.Server

	mu       sync.Mutex
	users    []fakeIAMUser
	denied   map[string]bool // action -> AccessDenied
	actions  []string
	statuses map[string]string // key id -> status after UpdateAccessKey
}

type fakeIAMUser struct {
	name, passwordLastUsed string
	keys                   map[string]string // id -> status
}

const fortikKeyID = "AKIAFORTIKSELF000001"

func newFakeIAM(t *testing.T) *fakeIAM {
	t.Helper()
	f := &fakeIAM{denied: map[string]bool{}, statuses: map[string]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIAM) resolved() integrations.Resolved {
	cm := map[string]any{"region": "us-east-1", "role_arn": "arn:aws:iam::123456789012:role/fortik-agents", "iam_endpoint": f.srv.URL}
	raw, _ := json.Marshal(cm)
	return integrations.Resolved{Integration: integrations.Integration{Key: "aws", System: "aws", Config: raw, Status: "configured"},
		ConfigMap: cm, Secrets: map[string]string{"access_key_id": fortikKeyID, "secret_access_key": "fortik-secret-do-not-leak"}}
}

func (f *fakeIAM) serve(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	act := r.PostForm.Get("Action")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.actions = append(f.actions, act)
	w.Header().Set("Content-Type", "text/xml")
	if f.denied[act] {
		w.WriteHeader(403)
		fmt.Fprintf(w, `<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>User is not authorized to perform iam:%s</Message></Error><RequestId>r</RequestId></ErrorResponse>`, act)
		return
	}
	switch act {
	case "ListUsers":
		var b strings.Builder
		for _, u := range f.users {
			pl := ""
			if u.passwordLastUsed != "" {
				pl = "<PasswordLastUsed>" + u.passwordLastUsed + "</PasswordLastUsed>"
			}
			fmt.Fprintf(&b, `<member><Path>/</Path><UserName>%s</UserName><UserId>AID%s</UserId><Arn>arn:aws:iam::123456789012:user/%s</Arn><CreateDate>2024-01-01T00:00:00Z</CreateDate>%s</member>`,
				u.name, strings.ToUpper(u.name), u.name, pl)
		}
		fmt.Fprintf(w, `<ListUsersResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><ListUsersResult><IsTruncated>false</IsTruncated><Users>%s</Users></ListUsersResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></ListUsersResponse>`, b.String())
	case "ListAccessKeys":
		name := r.PostForm.Get("UserName")
		var b strings.Builder
		for _, u := range f.users {
			if u.name != name {
				continue
			}
			for id, st := range u.keys {
				fmt.Fprintf(&b, `<member><UserName>%s</UserName><AccessKeyId>%s</AccessKeyId><Status>%s</Status><CreateDate>2024-02-01T00:00:00Z</CreateDate></member>`, name, id, st)
			}
		}
		fmt.Fprintf(w, `<ListAccessKeysResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><ListAccessKeysResult><IsTruncated>false</IsTruncated><AccessKeyMetadata>%s</AccessKeyMetadata></ListAccessKeysResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></ListAccessKeysResponse>`, b.String())
	case "GetAccessKeyLastUsed":
		fmt.Fprint(w, `<GetAccessKeyLastUsedResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><GetAccessKeyLastUsedResult><UserName>u</UserName><AccessKeyLastUsed><LastUsedDate>2026-10-19T03:00:00Z</LastUsedDate><ServiceName>s3</ServiceName><Region>us-east-1</Region></AccessKeyLastUsed></GetAccessKeyLastUsedResult><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></GetAccessKeyLastUsedResponse>`)
	case "UpdateAccessKey":
		f.statuses[r.PostForm.Get("AccessKeyId")] = r.PostForm.Get("Status")
		fmt.Fprint(w, `<UpdateAccessKeyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><ResponseMetadata><RequestId>r</RequestId></ResponseMetadata></UpdateAccessKeyResponse>`)
	default:
		w.WriteHeader(400)
		fmt.Fprint(w, `<ErrorResponse><Error><Type>Sender</Type><Code>InvalidAction</Code><Message>no</Message></Error><RequestId>r</RequestId></ErrorResponse>`)
	}
}

func TestAWSDiscoverAndRevoke(t *testing.T) {
	iam := newFakeIAM(t)
	iam.users = []fakeIAMUser{
		{name: "fortik-broker", keys: map[string]string{fortikKeyID: "Active"}},
		{name: "nightly-sync", keys: map[string]string{"AKIASYNC000000000001": "Active", "AKIASYNCOLD000000002": "Inactive"}},
		{name: "alice", passwordLastUsed: "2026-10-18T09:00:00Z", keys: map[string]string{"AKIAALICE00000000001": "Active"}},
	}
	src := pgrolestest.NewSource()
	d := discoverers.NewAWS(src, nil, nil)
	if res := d.Discover(bg); len(res) != 1 || res[0].Status != shadow.ScanNotConfigured {
		t.Fatalf("not configured: %+v", res)
	}
	src.Put(iam.resolved())
	svc, _, _ := newService(t, d)
	rep, err := svc.Scan(bg, "user:sec@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	var res shadow.ScanResult
	for _, r := range rep.Systems {
		if r.System == shadow.SystemAWS {
			res = r
		}
	}
	if res.Status != shadow.ScanScanned || res.Found != 2 || res.Flagged != 1 || !strings.Contains(res.Detail, "fortik-broker excluded") {
		t.Fatalf("aws result: %+v", res)
	}
	if strings.Contains(res.Detail, fortikKeyID) || strings.Contains(res.Detail, "fortik-secret") {
		t.Fatal("Fortik's key in the report")
	}
	sync := findByRef(t, svc, shadow.SystemAWS, shadow.KindIAMUserKey, "AKIASYNC000000000001")
	ev := evidence(sync)
	if !sync.UsedBySoftware || sync.Status != shadow.StatusFlagged || ev["last_used_service"] != "s3" || sync.Holder != "nightly-sync" {
		t.Fatalf("sync key: %+v %v", sync, ev)
	}
	if a := findByRef(t, svc, shadow.SystemAWS, shadow.KindIAMUserKey, "AKIAALICE00000000001"); a.UsedBySoftware {
		t.Fatalf("console user flagged: %+v", a)
	}
	for _, k := range []string{fortikKeyID, "AKIASYNCOLD000000002"} {
		if _, err := svc.Get(bg, shadow.FindingID(shadow.SystemAWS, shadow.KindIAMUserKey, k)); err == nil {
			t.Fatalf("%s recorded", k)
		}
	}

	// Denied: honest failure, key untouched.
	iam.mu.Lock()
	iam.denied["UpdateAccessKey"] = true
	iam.mu.Unlock()
	f, out, err := svc.Revoke(bg, sync.FindingID, "user:sec@example.com", "standing key in a cron job")
	if err != nil || out.Outcome != shadow.OutcomeNotRevoked || f.Status != shadow.StatusFlagged || !strings.Contains(out.Detail, "AccessDenied") {
		t.Fatalf("denied revoke: %v %+v", err, out)
	}
	iam.mu.Lock()
	iam.denied["UpdateAccessKey"] = false
	iam.mu.Unlock()
	f, out, err = svc.Revoke(bg, sync.FindingID, "user:sec@example.com", "standing key in a cron job")
	if err != nil || out.Outcome != shadow.OutcomeRevoked || f.Status != shadow.StatusRevoked {
		t.Fatalf("revoke: %v %+v", err, out)
	}
	iam.mu.Lock()
	st := iam.statuses["AKIASYNC000000000001"]
	iam.mu.Unlock()
	if st != "Inactive" {
		t.Fatalf("key status %q", st)
	}

	// ListUsers denied: not scanned, never "nothing found".
	iam.mu.Lock()
	iam.denied["ListUsers"] = true
	iam.mu.Unlock()
	if r := d.Discover(bg); r[0].Status != shadow.ScanError || !strings.Contains(r[0].Detail, "not scanned") {
		t.Fatalf("denied list: %+v", r)
	}
}
