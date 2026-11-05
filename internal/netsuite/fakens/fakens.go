// Package fakens is a LOCAL FAKE of the parts of NetSuite's REST web services
// Fortik uses, for automated tests and the demo only. It is NOT NetSuite and
// proves nothing about a real account. It implements:
//
//   - POST /services/rest/auth/oauth2/v1/token (client credentials with a
//     JWT assertion: alg PS256/ES256, kid, iss, aud, exp checked and the
//     signature verified against the configured public key)
//   - /services/rest/record/v1/{type}[/{id}]: GET, POST, PATCH, PUT, DELETE
//   - POST /services/rest/query/v1/suiteql for the queries Fortik issues
//     (employee lookups, system notes after an id, simple SELECT ... FROM <table>)
//   - POST /fake/direct-change: simulates a change made in NetSuite directly
//     (not through Fortik), which appears in the system notes
//   - GET /fake/state: record and request counters for assertions
package fakens

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const tokenPath = "/services/rest/auth/oauth2/v1/token"

// Fake is one fake account.
type Fake struct {
	ClientID      string
	CertificateID string
	PublicKey     crypto.PublicKey
	// BaseURL is the URL the fake is reachable at (the JWT audience is
	// BaseURL + token path); set it after the listener starts.
	BaseURL string
	// IntegrationEntity is the entity Fortik's own (gateway) changes are
	// recorded under in the system notes.
	IntegrationEntity string

	mu        sync.Mutex
	records   map[string]map[string]map[string]any // type -> id -> fields
	notes     []map[string]any
	tokens    map[string]time.Time
	nextID    int
	nextNote  int
	Requests  map[string]int
	BadTokens int
}

// New returns a seeded fake: customers, a vendor, and employees 3 and 4.
func New(clientID, certID string, pub crypto.PublicKey) *Fake {
	f := &Fake{ClientID: clientID, CertificateID: certID, PublicKey: pub, IntegrationEntity: "999",
		records: map[string]map[string]map[string]any{}, tokens: map[string]time.Time{}, nextID: 1000, nextNote: int(time.Now().Unix()), Requests: map[string]int{}}
	// System note ids keep increasing across restarts (as NetSuite's do), so a
	// stored sync cursor never hides a restarted fake's new notes.
	f.records["customer"] = map[string]map[string]any{
		"101": {"id": "101", "companyName": "Acme Retail", "phone": "+1 555 0101", "email": "ap@acme-retail.example"},
		"102": {"id": "102", "companyName": "Globex", "phone": "+1 555 0102", "email": "billing@globex.example"},
	}
	f.records["vendor"] = map[string]map[string]any{
		"201": {"id": "201", "companyName": "Initech Supplies", "email": "ar@initech.example", "achAccountNumber": "000123456789"},
	}
	f.records["employee"] = map[string]map[string]any{
		"3": {"id": "3", "entityid": "AI Agent - Order Assistant", "isinactive": "F"},
		"4": {"id": "4", "entityid": "AI Agent - AP Bot", "isinactive": "F"},
	}
	f.records["vendorbill"] = map[string]map[string]any{"301": {"id": "301", "entity": map[string]any{"id": "201"}, "total": 1200.0}}
	return f
}

func (f *Fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.Requests[r.Method+" "+route(r.URL.Path)]++
	f.mu.Unlock()
	switch {
	case r.URL.Path == tokenPath && r.Method == http.MethodPost:
		f.token(w, r)
	case r.URL.Path == "/fake/direct-change" && r.Method == http.MethodPost:
		f.directChange(w, r)
	case r.URL.Path == "/fake/state":
		f.state(w)
	case strings.HasPrefix(r.URL.Path, "/services/rest/"):
		if !f.authorized(r) {
			nsErr(w, http.StatusUnauthorized, "INVALID_LOGIN", "Invalid login attempt.")
			return
		}
		if r.URL.Path == "/services/rest/query/v1/suiteql" && r.Method == http.MethodPost {
			f.suiteql(w, r)
			return
		}
		if rest, ok := strings.CutPrefix(r.URL.Path, "/services/rest/record/v1/"); ok {
			f.record(w, r, rest)
			return
		}
		nsErr(w, http.StatusNotFound, "NONEXISTENT_ID", "Unknown resource.")
	default:
		http.NotFound(w, r)
	}
}

func route(p string) string {
	switch {
	case p == tokenPath:
		return "token"
	case strings.HasPrefix(p, "/services/rest/query/"):
		return "suiteql"
	case strings.HasPrefix(p, "/services/rest/record/v1/"):
		return "record"
	}
	return p
}

func nsErr(w http.ResponseWriter, status int, code, detail string) {
	w.Header().Set("Content-Type", "application/vnd.oracle.resource+json; type=error")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "https://www.rfc-editor.org/rfc/rfc9110.html", "title": http.StatusText(status), "status": status,
		"o:errorDetails": []map[string]any{{"detail": detail, "o:errorCode": code}}})
}

// --- OAuth 2.0 client credentials -------------------------------------------------

func (f *Fake) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	bad := func(desc string) {
		f.mu.Lock()
		f.BadTokens++
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": desc})
	}
	if r.PostForm.Get("grant_type") != "client_credentials" || r.PostForm.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		bad("unsupported grant")
		return
	}
	parts := strings.Split(r.PostForm.Get("client_assertion"), ".")
	if len(parts) != 3 {
		bad("malformed assertion")
		return
	}
	var hdr struct{ Alg, Kid string }
	var cl struct {
		Iss   string `json:"iss"`
		Aud   string `json:"aud"`
		Exp   int64  `json:"exp"`
		Iat   int64  `json:"iat"`
		Scope any    `json:"scope"`
	}
	if dec(parts[0], &hdr) != nil || dec(parts[1], &cl) != nil {
		bad("malformed assertion")
		return
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		bad("malformed signature")
		return
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	ok := false
	switch hdr.Alg {
	case "PS256":
		if k, isRSA := f.PublicKey.(*rsa.PublicKey); isRSA {
			ok = rsa.VerifyPSS(k, crypto.SHA256, sum[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil
		}
	case "ES256":
		if k, isEC := f.PublicKey.(*ecdsa.PublicKey); isEC && len(sig) == 64 {
			ok = ecdsa.Verify(k, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
		}
	}
	now := time.Now().Unix()
	switch {
	case !ok:
		bad("signature verification failed")
	case hdr.Kid != f.CertificateID:
		bad("unknown certificate id")
	case cl.Iss != f.ClientID:
		bad("unknown client")
	case cl.Aud != f.BaseURL+tokenPath:
		bad("wrong audience")
	case cl.Exp <= now || cl.Exp-cl.Iat > 3600:
		bad("assertion expired or valid too long")
	case !strings.Contains(fmt.Sprint(cl.Scope), "rest_webservices"):
		bad("scope rest_webservices required")
	default:
		f.mu.Lock()
		f.nextID++
		tok := fmt.Sprintf("fake-ns-token-%d", f.nextID)
		f.tokens[tok] = time.Now().Add(time.Hour)
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": tok, "token_type": "Bearer", "expires_in": "3600"})
	}
}

func dec(s string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func (f *Fake) authorized(r *http.Request) bool {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	f.mu.Lock()
	defer f.mu.Unlock()
	exp, known := f.tokens[tok]
	return ok && known && time.Now().Before(exp)
}

// --- records -------------------------------------------------------------------------

func (f *Fake) record(w http.ResponseWriter, r *http.Request, rest string) {
	parts := strings.Split(strings.TrimSuffix(rest, "/"), "/")
	typ := strings.ToLower(parts[0])
	f.mu.Lock()
	defer f.mu.Unlock()
	recs := f.records[typ]
	switch {
	case len(parts) == 1 && r.Method == http.MethodGet:
		items := []map[string]any{}
		ids := make([]string, 0, len(recs))
		for id := range recs {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			items = append(items, map[string]any{"id": id})
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items, "count": len(items), "hasMore": false})
	case len(parts) == 1 && r.Method == http.MethodPost:
		body := map[string]any{}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			nsErr(w, http.StatusBadRequest, "INVALID_CONTENT", "Invalid JSON.")
			return
		}
		f.nextID++
		id := strconv.Itoa(f.nextID)
		body["id"] = id
		if f.records[typ] == nil {
			f.records[typ] = map[string]map[string]any{}
		}
		f.records[typ][id] = body
		f.note(f.IntegrationEntity, typ, id, "create")
		w.Header().Set("Location", f.BaseURL+"/services/rest/record/v1/"+typ+"/"+id)
		w.WriteHeader(http.StatusNoContent)
	case len(parts) == 2:
		rec, ok := recs[parts[1]]
		switch r.Method {
		case http.MethodGet:
			if !ok {
				nsErr(w, http.StatusNotFound, "NONEXISTENT_ID", "The record instance does not exist.")
				return
			}
			writeJSON(w, http.StatusOK, rec)
		case http.MethodPatch, http.MethodPut:
			if !ok && r.Method == http.MethodPatch {
				nsErr(w, http.StatusNotFound, "NONEXISTENT_ID", "The record instance does not exist.")
				return
			}
			body := map[string]any{}
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				nsErr(w, http.StatusBadRequest, "INVALID_CONTENT", "Invalid JSON.")
				return
			}
			if !ok {
				rec = map[string]any{"id": parts[1]}
				f.records[typ][parts[1]] = rec
			}
			for k, v := range body {
				if v == nil {
					delete(rec, k)
				} else {
					rec[k] = v
				}
				f.note(f.IntegrationEntity, typ, parts[1], k)
			}
			w.WriteHeader(http.StatusNoContent)
		case http.MethodDelete:
			if !ok {
				nsErr(w, http.StatusNotFound, "NONEXISTENT_ID", "The record instance does not exist.")
				return
			}
			delete(recs, parts[1])
			f.note(f.IntegrationEntity, typ, parts[1], "delete")
			w.WriteHeader(http.StatusNoContent)
		default:
			nsErr(w, http.StatusMethodNotAllowed, "INVALID_REQUEST", "Method not allowed.")
		}
	case len(parts) == 4 && parts[2] == "!transform" && r.Method == http.MethodPost:
		f.nextID++
		id := strconv.Itoa(f.nextID)
		to := strings.ToLower(parts[3])
		if f.records[to] == nil {
			f.records[to] = map[string]map[string]any{}
		}
		f.records[to][id] = map[string]any{"id": id, "createdFrom": parts[1]}
		f.note(f.IntegrationEntity, to, id, "create")
		w.WriteHeader(http.StatusNoContent)
	default:
		nsErr(w, http.StatusNotFound, "NONEXISTENT_ID", "Unknown resource.")
	}
}

// recordTypeIDs are the fake's numeric record type ids in system notes.
var recordTypeIDs = map[string]string{"customer": "-2", "vendor": "-3", "employee": "-4", "vendorbill": "-20", "vendorpayment": "-21"}

func (f *Fake) note(entity, typ, id, field string) {
	f.nextNote++
	f.notes = append(f.notes, map[string]any{"id": strconv.Itoa(f.nextNote), "date": time.Now().UTC().Format(time.RFC3339),
		"field": field, "name": entity, "recordid": id, "recordtypeid": recordTypeIDs[typ], "role": "3", "context": "Web Services"})
}

// directChange simulates an agent changing a record in NetSuite directly.
func (f *Fake) directChange(w http.ResponseWriter, r *http.Request) {
	var in struct{ Entity, RecordType, RecordID, Field string }
	if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in) != nil || in.Entity == "" {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.note(in.Entity, strings.ToLower(in.RecordType), in.RecordID, in.Field)
	n := f.notes[len(f.notes)-1]
	f.mu.Unlock()
	writeJSON(w, http.StatusOK, n)
}

func (f *Fake) state(w http.ResponseWriter) {
	f.mu.Lock()
	defer f.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"records": f.records, "requests": f.Requests, "bad_tokens": f.BadTokens, "system_notes": len(f.notes)})
}

// Record returns a copy of one record (tests).
func (f *Fake) Record(typ, id string) (map[string]any, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.records[typ][id]
	if !ok {
		return nil, false
	}
	out := map[string]any{}
	for k, v := range r {
		out[k] = v
	}
	return out, true
}

// --- SuiteQL ---------------------------------------------------------------------------

var (
	inRe    = regexp.MustCompile(`(?i)\bid\s+IN\s*\(([^)]*)\)`)
	noteRe  = regexp.MustCompile(`(?i)FROM\s+systemnote\s+WHERE\s+id\s*>\s*([0-9]+)\s+AND\s+name\s+IN\s*\(([^)]*)\)`)
	tableRe = regexp.MustCompile(`(?i)\bFROM\s+([A-Za-z_][A-Za-z0-9_]*)`)
)

func (f *Fake) suiteql(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Prefer") != "transient" {
		nsErr(w, http.StatusBadRequest, "INVALID_HEADER", "SuiteQL requires the header Prefer: transient.")
		return
	}
	var in struct {
		Q string `json:"q"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.Q == "" {
		nsErr(w, http.StatusBadRequest, "INVALID_CONTENT", "Missing query.")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if limit <= 0 || limit > 1000 {
		limit = 1000
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var items []map[string]any
	switch {
	case noteRe.MatchString(in.Q):
		m := noteRe.FindStringSubmatch(in.Q)
		after, _ := strconv.Atoi(m[1])
		names := splitIDs(m[2])
		for _, n := range f.notes {
			id, _ := strconv.Atoi(n["id"].(string))
			if id > after && names[n["name"].(string)] {
				items = append(items, n)
			}
		}
	default:
		t := tableRe.FindStringSubmatch(in.Q)
		if t == nil {
			nsErr(w, http.StatusBadRequest, "INVALID_SEARCH", "Invalid search query.")
			return
		}
		table := strings.ToLower(t[1])
		recs, known := f.records[table]
		if !known && table != "systemnote" {
			nsErr(w, http.StatusBadRequest, "INVALID_SEARCH", fmt.Sprintf("Record '%s' was not found.", table))
			return
		}
		var only map[string]bool
		if m := inRe.FindStringSubmatch(in.Q); m != nil {
			only = splitIDs(m[1])
		}
		ids := make([]string, 0, len(recs))
		for id := range recs {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			if only == nil || only[id] {
				items = append(items, recs[id])
			}
		}
	}
	total := len(items)
	if offset > total {
		offset = total
	}
	end := min(offset+limit, total)
	page := items[offset:end]
	if page == nil {
		page = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": page, "count": len(page), "offset": offset, "totalResults": total, "hasMore": end < total})
}

func splitIDs(s string) map[string]bool {
	out := map[string]bool{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.Trim(strings.TrimSpace(p), "'"); p != "" {
			out[p] = true
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
