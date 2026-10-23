package shadow_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"fortik/internal/authz"
	"fortik/internal/shadow"
)

func doAPI(t *testing.T, h http.Handler, role, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if role != "" {
		r = r.WithContext(authz.With(r.Context(), authz.Principal{Kind: authz.KindUser, Name: role, Email: role + "@example.com",
			Roles: map[string]bool{role: true}}))
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestHTTPRolesAndStrictJSON(t *testing.T) {
	e := newEnv(t)
	e.pg.set(shadow.ScanResult{System: shadow.SystemPostgres, Status: shadow.ScanScanned, Credentials: []shadow.Credential{scriptRole()}})
	mux := http.NewServeMux()
	shadow.NewHandler(e.svc, nil).Register(mux)
	fid := shadow.FindingID(shadow.SystemPostgres, shadow.KindDBRole, "acme/nightly_sync_script")

	if w := doAPI(t, mux, "", "GET", "/v1/shadow", ""); w.Code != 401 {
		t.Fatalf("anonymous list: %d", w.Code)
	}
	if w := doAPI(t, mux, authz.RoleAuditor, "POST", "/v1/shadow/scan", ""); w.Code != 403 {
		t.Fatalf("auditor scan: %d", w.Code)
	}
	if w := doAPI(t, mux, authz.RoleSecurity, "POST", "/v1/shadow/scan", `{"x":1}`); w.Code != 400 {
		t.Fatalf("scan with unknown field: %d", w.Code)
	}
	if w := doAPI(t, mux, authz.RoleSecurity, "POST", "/v1/shadow/scan", `{}`); w.Code != 200 {
		t.Fatalf("scan {}: %d", w.Code)
	}
	w := doAPI(t, mux, authz.RoleSecurity, "POST", "/v1/shadow/scan", `{"reason":"weekly review"}`)
	if w.Code != 200 {
		t.Fatalf("scan: %d %s", w.Code, w.Body)
	}
	var rep shadow.Report
	if err := json.Unmarshal(w.Body.Bytes(), &rep); err != nil || rep.Reason != "weekly review" {
		t.Fatalf("scan report: %v %s", err, w.Body)
	}
	w = doAPI(t, mux, authz.RoleAuditor, "GET", "/v1/shadow?status=flagged_for_revocation", "")
	var list struct {
		Findings []shadow.Finding `json:"findings"`
		LastScan *shadow.Report   `json:"last_scan"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &list) != nil || len(list.Findings) != 1 || list.LastScan == nil {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	// The console's field names.
	for _, k := range []string{`"finding_id"`, `"system"`, `"kind"`, `"credential_id":"acme/nightly_sync_script"`, `"holder"`, `"used_by_software":true`,
		`"evidence"`, `"status"`, `"discovered_agent_id":"shadow_postgres_`, `"created_at"`, `"last_seen"`} {
		if !strings.Contains(w.Body.String(), k) {
			t.Fatalf("list JSON lacks %s: %s", k, w.Body)
		}
	}
	for _, q := range []string{"?status=bogus", "?system=x", "?limit=0", "?foo=1", "?agent_id=%20bad"} {
		if w := doAPI(t, mux, authz.RoleAuditor, "GET", "/v1/shadow"+q, ""); w.Code != 400 {
			t.Fatalf("list %s: %d", q, w.Code)
		}
	}
	if w := doAPI(t, mux, authz.RoleAuditor, "GET", "/v1/shadow/"+fid, ""); w.Code != 200 {
		t.Fatalf("get: %d", w.Code)
	}
	if w := doAPI(t, mux, authz.RoleAuditor, "GET", "/v1/shadow/shf_nothere", ""); w.Code != 404 {
		t.Fatalf("get unknown: %d", w.Code)
	}
	for _, p := range []string{"revoke", "dismiss", "register"} {
		if w := doAPI(t, mux, authz.RoleAuditor, "POST", "/v1/shadow/"+fid+"/"+p, `{"reason":"x"}`); w.Code != 403 {
			t.Fatalf("auditor %s: %d", p, w.Code)
		}
	}
	e.pg.rev = shadow.RevokeResult{Outcome: shadow.OutcomeNotRevoked, Detail: "permission denied"}
	for _, b := range []string{"", "{}"} {
		w := doAPI(t, mux, authz.RoleSecurity, "POST", "/v1/shadow/"+fid+"/revoke", b)
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"revoked":false`) || !strings.Contains(w.Body.String(), `"status":"flagged_for_revocation"`) {
			t.Fatalf("revoke %q: %d %s", b, w.Code, w.Body)
		}
	}
	if w := doAPI(t, mux, authz.RoleSecurity, "POST", "/v1/shadow/"+fid+"/revoke", `{"reason":"x","force":true}`); w.Code != 400 {
		t.Fatalf("revoke unknown field: %d", w.Code)
	}
	e.pg.rev = shadow.RevokeResult{Outcome: shadow.OutcomeRevoked, Detail: "done"}
	w = doAPI(t, mux, authz.RoleSecurity, "POST", "/v1/shadow/"+fid+"/revoke", `{"reason":"standing password in a cron script"}`)
	var rv struct {
		Finding shadow.Finding `json:"finding"`
		Outcome string         `json:"outcome"`
		Revoked bool           `json:"revoked"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &rv) != nil || !rv.Revoked || rv.Finding.Status != shadow.StatusRevoked ||
		rv.Finding.UpdatedBy != "user:security@example.com" {
		t.Fatalf("revoke: %d %s", w.Code, w.Body)
	}
	if w := doAPI(t, mux, authz.RoleSecurity, "POST", "/v1/shadow/"+fid+"/dismiss", `{"reason":"x"}`); w.Code != 409 {
		t.Fatalf("dismiss revoked: %d", w.Code)
	}
	if w := doAPI(t, mux, authz.RoleSecurity, "POST", "/v1/shadow/"+fid+"/register", `{"sponsor":"bad","name":"n"}`); w.Code != 400 {
		t.Fatalf("register bad sponsor: %d", w.Code)
	}
	w = doAPI(t, mux, authz.RoleSecurity, "POST", "/v1/shadow/"+fid+"/register", `{"sponsor":"o@example.com","name":"Nightly sync","team":"data"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"registered"`) {
		t.Fatalf("register: %d %s", w.Code, w.Body)
	}
}
