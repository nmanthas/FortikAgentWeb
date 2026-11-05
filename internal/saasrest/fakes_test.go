package saasrest

// LOCAL FAKES of the Salesforce, ServiceNow and SAP APIs, implementing only
// the documented shapes Fortik uses. They prove Fortik's side (auth flows,
// probes, gateway enforcement), never the providers' behaviour.

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

type fakeBase struct {
	mu       sync.Mutex
	tokens   map[string]bool
	requests []string // "METHOD path" received with a valid token
	bodies   []string
	seq      int
}

func (f *fakeBase) issue(prefix string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.tokens == nil {
		f.tokens = map[string]bool{}
	}
	f.seq++
	t := fmt.Sprintf("%s-token-%d", prefix, f.seq)
	f.tokens[t] = true
	return t
}

func (f *fakeBase) valid(r *http.Request) bool {
	t, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	f.mu.Lock()
	defer f.mu.Unlock()
	return ok && f.tokens[t]
}

func (f *fakeBase) note(r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	f.bodies = append(f.bodies, string(b))
}

func (f *fakeBase) count(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.requests {
		if strings.HasPrefix(r, prefix) {
			n++
		}
	}
	return n
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// fakeSalesforce: the client credentials and JWT bearer token flows, the
// versions list, sobjects, limits and record CRUD.
type fakeSalesforce struct {
	fakeBase
	ClientID, ClientSecret, Username, Audience string
	PublicKey                                  *rsa.PublicKey
	NoSObjects                                 bool // the run-as user lacks API access (403)

	// Agent API (LOCAL FAKE of the shapes Salesforce's own client uses):
	// a separate app whose client credentials yield a JWT-shaped token.
	AgentClientID, AgentClientSecret string
	Agents                           map[string]string // BotDefinition id -> label
	agentSessions                    map[string]string // session id -> agent id
	StartBodies                      []map[string]any
}

// agentJWT is a JWT-shaped token (unsigned: the fake only checks it is one
// it issued) carrying the Agent API scopes.
func (f *fakeSalesforce) agentJWT(scope string) string {
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	f.mu.Lock()
	f.seq++
	n := f.seq
	f.mu.Unlock()
	tok := enc(map[string]string{"alg": "RS256", "typ": "JWT"}) + "." + enc(map[string]any{"sub": "005xx", "iss": "https://login.salesforce.com", "scope": scope, "n": n}) + ".sfagentsig"
	f.mu.Lock()
	if f.tokens == nil {
		f.tokens = map[string]bool{}
	}
	f.tokens[tok] = true
	f.mu.Unlock()
	return tok
}

func (f *fakeSalesforce) agentAPI(w http.ResponseWriter, r *http.Request) {
	if !strings.HasSuffix(r.Header.Get("Authorization"), ".sfagentsig") {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "LOCAL FAKE: the Agent API needs a JWT access token"})
		return
	}
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+r.URL.Path)
	f.bodies = append(f.bodies, string(b))
	if f.agentSessions == nil {
		f.agentSessions = map[string]string{}
	}
	f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/einstein/ai-agent/v1/")
	parts := strings.Split(path, "/")
	switch {
	case r.Method == http.MethodPost && len(parts) == 3 && parts[0] == "agents" && parts[2] == "sessions":
		if _, ok := f.Agents[parts[1]]; !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"message": "LOCAL FAKE: agent not found"})
			return
		}
		var body map[string]any
		if json.Unmarshal(b, &body) != nil || body["externalSessionKey"] == nil || body["instanceConfig"] == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "LOCAL FAKE: externalSessionKey and instanceConfig are required"})
			return
		}
		f.mu.Lock()
		f.StartBodies = append(f.StartBodies, body)
		f.seq++
		sid := fmt.Sprintf("0a1b2c3d-0000-4000-8000-%012d", f.seq)
		f.agentSessions[sid] = parts[1]
		f.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"sessionId": sid, "messages": []map[string]string{{"type": "Inform", "message": "Hi, I am " + f.Agents[parts[1]] + "."}}})
	case r.Method == http.MethodPost && len(parts) == 3 && parts[0] == "sessions" && parts[2] == "messages":
		f.mu.Lock()
		_, ok := f.agentSessions[parts[1]]
		f.mu.Unlock()
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"message": "LOCAL FAKE: session not found"})
			return
		}
		var body struct {
			Message struct {
				SequenceID json.Number `json:"sequenceId"`
				Type, Text string
			} `json:"message"`
			Variables []any `json:"variables"`
		}
		if json.Unmarshal(b, &body) != nil || body.Message.Type != "Text" || body.Message.Text == "" || body.Message.SequenceID == "" || body.Variables == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "LOCAL FAKE: message.sequenceId, type Text, text and variables are required"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"messages": []map[string]string{{"type": "Inform", "message": "echo: " + body.Message.Text, "planId": "p1"}}})
	case r.Method == http.MethodDelete && len(parts) == 2 && parts[0] == "sessions":
		if r.Header.Get("X-Session-End-Reason") == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "LOCAL FAKE: x-session-end-reason is required"})
			return
		}
		f.mu.Lock()
		delete(f.agentSessions, parts[1])
		f.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"messages": []map[string]string{{"type": "SessionEnded"}}})
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"message": "LOCAL FAKE: not found"})
	}
}

func (f *fakeSalesforce) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/services/oauth2/token" && r.Method == http.MethodPost {
		_ = r.ParseForm()
		ok := false
		switch r.PostForm.Get("grant_type") {
		case "client_credentials":
			if f.AgentClientID != "" && r.PostForm.Get("client_id") == f.AgentClientID && r.PostForm.Get("client_secret") == f.AgentClientSecret {
				writeJSON(w, http.StatusOK, map[string]string{"access_token": f.agentJWT("api chatbot_api sfap_api refresh_token"), "token_type": "Bearer",
					"id": "https://login.salesforce.com/id/00Dxx0000001gPL/005xx000001X8Uz"})
				return
			}
			ok = r.PostForm.Get("client_id") == f.ClientID && r.PostForm.Get("client_secret") == f.ClientSecret
		case "urn:ietf:params:oauth:grant-type:jwt-bearer":
			ok = f.verifyJWT(r.PostForm.Get("assertion"))
		}
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client", "error_description": "LOCAL FAKE: invalid client credentials"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"access_token": f.issue("sf"), "instance_url": "http://" + r.Host,
			"id": "https://login.salesforce.com/id/00Dxx0000001gPL/005xx000001X8Uz", "token_type": "Bearer"})
		return
	}
	if strings.HasPrefix(r.URL.Path, "/einstein/ai-agent/v1/") {
		if !f.valid(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"message": "LOCAL FAKE: invalid token"})
			return
		}
		f.agentAPI(w, r)
		return
	}
	if !f.valid(r) {
		writeJSON(w, http.StatusUnauthorized, []map[string]string{{"errorCode": "INVALID_SESSION_ID", "message": "Session expired or invalid"}})
		return
	}
	f.note(r)
	switch {
	case r.URL.Path == "/services/data/v62.0/query" && strings.Contains(r.URL.Query().Get("q"), "FROM BotDefinition"):
		recs := []map[string]string{}
		for id, label := range f.Agents {
			recs = append(recs, map[string]string{"Id": id, "DeveloperName": strings.ReplaceAll(label, " ", "_"), "MasterLabel": label, "AgentType": "ExternalCopilot"})
		}
		writeJSON(w, http.StatusOK, map[string]any{"totalSize": len(recs), "done": true, "records": recs})
	case r.URL.Path == "/services/data/":
		writeJSON(w, http.StatusOK, []map[string]string{{"version": "61.0"}, {"version": "62.0"}})
	case r.URL.Path == "/services/data/v62.0/sobjects":
		if f.NoSObjects {
			writeJSON(w, http.StatusForbidden, []map[string]string{{"errorCode": "API_DISABLED_FOR_ORG", "message": "API is not enabled for this Organization or Partner"}})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"sobjects": []map[string]any{
			{"name": "Account", "queryable": true, "createable": true, "updateable": true, "deletable": false},
			{"name": "Contact", "queryable": true, "createable": false, "updateable": false, "deletable": false},
			{"name": "Secret__c", "queryable": false},
		}})
	case r.URL.Path == "/services/data/v62.0/limits":
		writeJSON(w, http.StatusOK, map[string]any{"DailyApiRequests": map[string]int{"Max": 15000, "Remaining": 14990}})
	case strings.HasPrefix(r.URL.Path, "/services/data/v62.0/sobjects/Account/"):
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, http.StatusOK, map[string]string{"Id": "001xx", "Name": "Acme"})
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	default:
		writeJSON(w, http.StatusNotFound, []map[string]string{{"errorCode": "NOT_FOUND", "message": "The requested resource does not exist"}})
	}
}

func (f *fakeSalesforce) verifyJWT(a string) bool {
	parts := strings.Split(a, ".")
	if len(parts) != 3 || f.PublicKey == nil {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(f.PublicKey, crypto.SHA256, sum[:], sig) != nil {
		return false
	}
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c struct {
		Iss, Sub, Aud string
		Exp           int64
	}
	return json.Unmarshal(raw, &c) == nil && c.Iss == f.ClientID && c.Sub == f.Username && c.Aud == f.Audience && c.Exp > 0
}

// fakeServiceNow: Basic auth or a client-credentials token, the Table API.
type fakeServiceNow struct {
	fakeBase
	User, Password, ClientID, ClientSecret string
	Forbidden                              map[string]bool // tables the user has no ACL for
}

func (f *fakeServiceNow) authorized(r *http.Request) bool {
	if u, p, ok := r.BasicAuth(); ok {
		return u == f.User && p == f.Password
	}
	return f.valid(r)
}

func (f *fakeServiceNow) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/oauth_token.do" && r.Method == http.MethodPost {
		_ = r.ParseForm()
		if r.PostForm.Get("grant_type") != "client_credentials" || r.PostForm.Get("client_id") != f.ClientID || r.PostForm.Get("client_secret") != f.ClientSecret {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "access_denied", "error_description": "LOCAL FAKE"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"access_token": f.issue("sn"), "token_type": "Bearer", "expires_in": 1799})
		return
	}
	if !f.authorized(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]string{"message": "User Not Authenticated"}, "status": "failure"})
		return
	}
	f.note(r)
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/now/table/"), "/")
	table := parts[0]
	switch {
	case !strings.HasPrefix(r.URL.Path, "/api/now/table/"):
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]string{"message": "Requested URI does not represent any resource"}})
	case f.Forbidden[table]:
		writeJSON(w, http.StatusForbidden, map[string]any{"error": map[string]string{"message": "Operation Failed: insufficient rights"}})
	case table == "no_such":
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]string{"message": "Invalid table no_such"}})
	case r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"result": []map[string]string{{"sys_id": "abc123"}}})
	case r.Method == http.MethodDelete:
		w.WriteHeader(http.StatusNoContent)
	default:
		writeJSON(w, http.StatusOK, map[string]any{"result": map[string]string{"sys_id": "abc123"}})
	}
}

// fakeSAP: Basic auth, OData $metadata, and the CSRF token dance for changes.
type fakeSAP struct {
	fakeBase
	User, Password string
	csrf           string
}

const sapMetadata = `<?xml version="1.0" encoding="utf-8"?><edmx:Edmx Version="1.0"><edmx:DataServices><Schema>
<EntityContainer Name="API_BUSINESS_PARTNER_Entities"><EntitySet Name="A_BusinessPartner" EntityType="x"/><EntitySet Name="A_BusinessPartnerAddress" EntityType="y"/></EntityContainer>
</Schema></edmx:DataServices></edmx:Edmx>`

func (f *fakeSAP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if u, p, ok := r.BasicAuth(); !ok || u != f.User || p != f.Password {
		w.Header().Set("WWW-Authenticate", `Basic realm="SAP NetWeaver Application Server"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	const svc = "/sap/opu/odata/sap/API_BUSINESS_PARTNER"
	if !strings.HasPrefix(r.URL.Path, svc) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if r.Method == http.MethodGet && strings.EqualFold(r.Header.Get("X-CSRF-Token"), "Fetch") {
		f.mu.Lock()
		f.csrf = "csrf-" + fmt.Sprint(len(f.requests)+1)
		tok := f.csrf
		f.mu.Unlock()
		w.Header().Set("X-CSRF-Token", tok)
		http.SetCookie(w, &http.Cookie{Name: "SAP_SESSIONID", Value: "s1"})
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodGet {
		f.mu.Lock()
		want := f.csrf
		f.mu.Unlock()
		c, err := r.Cookie("SAP_SESSIONID")
		if want == "" || r.Header.Get("X-CSRF-Token") != want || err != nil || c.Value != "s1" {
			w.Header().Set("X-CSRF-Token", "Required")
			w.WriteHeader(http.StatusForbidden)
			return
		}
	}
	f.note(r)
	switch {
	case strings.HasSuffix(r.URL.Path, "/$metadata"):
		w.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(w, sapMetadata)
	case r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"d": map[string]string{"BusinessPartner": "1000001"}})
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}
