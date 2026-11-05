// Command fakesaas serves LOCAL FAKES of the Salesforce, ServiceNow and SAP
// APIs and MCP servers for scripts/verify-saas-connections.sh, on one port
// each. They implement only the documented shapes Fortik uses; they are not
// the providers. Credentials are generated and written to -secrets-out
// (0600) for the script; /fake/calls reports what each fake received (never
// a credential).
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"fortik/internal/mcpclient/mcpfake"
)

type recorder struct {
	mu    sync.Mutex
	calls []string
}

func (r *recorder) add(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, s)
}

func (r *recorder) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

func gen(prefix string) string {
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func main() {
	sfPort := flag.Int("salesforce-port", 18501, "fake Salesforce (REST + Hosted MCP + OAuth)")
	snPort := flag.Int("servicenow-port", 18502, "fake ServiceNow (REST + MCP)")
	sapPort := flag.Int("sap-port", 18503, "fake SAP (OData + customer-managed MCP)")
	out := flag.String("secrets-out", "", "write the generated credentials here as JSON (0600)")
	redirect := flag.String("redirect", "http://127.0.0.1:8080/v1/oauth/mcp/callback", "Fortik's OAuth redirect URI for the fake Salesforce app")
	flag.Parse()

	creds := map[string]string{
		"sf_client_id": "fake-sf-client", "sf_client_secret": gen("sfsec-"),
		"sn_user": "fortik.integration", "sn_password": gen("snpw-"),
		"sap_user": "COMM_USER", "sap_password": gen("sappw-"),
		"sn_mcp_client": "fake-sn-mcp", "sn_mcp_secret": gen("snmcp-"),
		"sap_mcp_token": gen("sapmcp-"),
	}
	if *out != "" {
		b, _ := json.Marshal(creds)
		if err := os.WriteFile(*out, b, 0o600); err != nil {
			log.Fatal(err)
		}
	}
	rec := map[string]*recorder{"salesforce": {}, "servicenow": {}, "sap": {}}

	// Salesforce: OAuth client credentials (REST) and authorization code
	// (Hosted MCP) on the My Domain host, the REST API and an MCP server.
	sfMCP := &mcpfake.Server{Token: "nobody-yet", ReadWrite: true}
	sfOAuth := &mcpfake.OAuthServer{MCP: sfMCP, ClientID: creds["sf_client_id"], ClientSecret: creds["sf_client_secret"],
		RedirectURI:   *redirect,
		AuthorizePath: "/services/oauth2/authorize", TokenPath: "/services/oauth2/token", RevokePath: "/services/oauth2/revoke", MCPPrefix: "/platform/mcp/"}
	sf := http.NewServeMux()
	sf.Handle("/services/oauth2/", sfOAuth)
	sf.Handle("/platform/mcp/", sfOAuth)
	sf.HandleFunc("/services/data/", func(w http.ResponseWriter, r *http.Request) {
		tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !sfOAuth.ValidClientToken(tok) {
			writeJSON(w, 401, []map[string]string{{"errorCode": "INVALID_SESSION_ID", "message": "Session expired or invalid"}})
			return
		}
		rec["salesforce"].add(r.Method + " " + r.URL.Path)
		switch {
		case r.URL.Path == "/services/data/":
			writeJSON(w, 200, []map[string]string{{"version": "61.0"}, {"version": "62.0"}})
		case r.URL.Path == "/services/data/v62.0/sobjects":
			writeJSON(w, 200, map[string]any{"sobjects": []map[string]any{{"name": "Account", "queryable": true, "createable": true, "updateable": true}, {"name": "Contact", "queryable": true}}})
		case r.URL.Path == "/services/data/v62.0/limits":
			writeJSON(w, 200, map[string]any{"DailyApiRequests": map[string]int{"Max": 15000, "Remaining": 14999}})
		case strings.HasPrefix(r.URL.Path, "/services/data/v62.0/sobjects/Account/") && r.Method == http.MethodGet:
			writeJSON(w, 200, map[string]string{"Id": "001FAKE", "Name": "LOCAL FAKE account"})
		case strings.HasPrefix(r.URL.Path, "/services/data/v62.0/sobjects/Account/"):
			w.WriteHeader(204)
		default:
			writeJSON(w, 404, []map[string]string{{"errorCode": "NOT_FOUND", "message": "LOCAL FAKE"}})
		}
	})

	// ServiceNow: Basic auth and the Table API; an MCP server with client credentials.
	snMCP := &mcpfake.Server{Token: "nobody-yet"}
	snOAuth := &mcpfake.OAuthServer{MCP: snMCP, ClientID: creds["sn_mcp_client"], ClientSecret: creds["sn_mcp_secret"], TokenPath: "/oauth_token.do",
		MCPPrefix: "/sncapps/", ClientCredsForMCP: true}
	sn := http.NewServeMux()
	sn.Handle("/oauth_token.do", snOAuth)
	sn.Handle("/sncapps/", snOAuth)
	sn.HandleFunc("/api/now/", func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != creds["sn_user"] || p != creds["sn_password"] {
			writeJSON(w, 401, map[string]any{"error": map[string]string{"message": "User Not Authenticated"}})
			return
		}
		rec["servicenow"].add(r.Method + " " + r.URL.Path)
		if strings.HasPrefix(r.URL.Path, "/api/now/table/change_request") {
			writeJSON(w, 403, map[string]any{"error": map[string]string{"message": "Operation Failed: insufficient rights"}})
			return
		}
		writeJSON(w, 200, map[string]any{"result": []map[string]string{{"sys_id": "fake0001"}}})
	})

	// SAP: Basic auth, OData $metadata; a customer-managed MCP server with a bearer token.
	sapMCP := &mcpfake.Server{Token: creds["sap_mcp_token"]}
	sap := http.NewServeMux()
	sap.Handle("/mcp", sapMCP)
	sap.HandleFunc("/sap/opu/odata/sap/", func(w http.ResponseWriter, r *http.Request) {
		auth, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(r.Header.Get("Authorization"), "Basic "))
		if string(auth) != creds["sap_user"]+":"+creds["sap_password"] {
			w.WriteHeader(401)
			return
		}
		rec["sap"].add(r.Method + " " + r.URL.Path)
		if !strings.HasPrefix(r.URL.Path, "/sap/opu/odata/sap/API_BUSINESS_PARTNER") {
			w.WriteHeader(404)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/$metadata") {
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, `<edmx:Edmx><edmx:DataServices><Schema><EntityContainer><EntitySet Name="A_BusinessPartner"/><EntitySet Name="A_BusinessPartnerAddress"/></EntityContainer></Schema></edmx:DataServices></edmx:Edmx>`)
			return
		}
		writeJSON(w, 200, map[string]any{"d": map[string]string{"BusinessPartner": "FAKE1"}})
	})

	calls := func(name string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, 200, map[string]any{"calls": rec[name].list(), "revoked": len(sfOAuth.Revoked())})
		}
	}
	sf.HandleFunc("/fake/calls", calls("salesforce"))
	sn.HandleFunc("/fake/calls", calls("servicenow"))
	sap.HandleFunc("/fake/calls", calls("sap"))
	errc := make(chan error, 3)
	for port, h := range map[int]http.Handler{*sfPort: sf, *snPort: sn, *sapPort: sap} {
		go func(port int, h http.Handler) { errc <- http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", port), h) }(port, h)
	}
	log.Printf("LOCAL FAKES: salesforce :%d, servicenow :%d, sap :%d", *sfPort, *snPort, *sapPort)
	log.Fatal(<-errc)
}
