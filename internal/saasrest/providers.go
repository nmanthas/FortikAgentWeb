package saasrest

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"fortik/internal/integrations"
)

// Settings is one REST connection's configuration with its credentials.
type Settings struct {
	Key           string
	System        string // salesforce | servicenow | sap
	IntegrationID string
	Version       time.Time

	Base string // API base URL without a trailing slash
	Auth string // client_credentials | jwt_bearer | basic | oauth_client_credentials

	ClientID, ClientSecret, Username, Password, PrivateKeyPEM string
	Audience, TokenURL, Scope                                 string

	APIVersion string   // salesforce
	Tables     []string // servicenow
	Services   []string // sap
	SAPClient  string   // sap
	Product    string   // sap
}

// errSettings: the stored settings cannot be used (a required credential is
// missing); reported as invalid_settings, never sent upstream.
var errSettings = errors.New("invalid settings")

func settingsFrom(r integrations.Resolved) (Settings, error) {
	str := func(k string) string { v, _ := r.ConfigMap[k].(string); return strings.TrimSpace(v) }
	list := func(k string) []string {
		var out []string
		switch v := r.ConfigMap[k].(type) {
		case []string:
			out = v
		case []any:
			for _, x := range v {
				if s, ok := x.(string); ok {
					out = append(out, s)
				}
			}
		}
		return out
	}
	st := Settings{Key: r.Key, System: r.System, IntegrationID: r.IntegrationID, Version: r.UpdatedAt,
		ClientID: str("client_id"), ClientSecret: r.Secrets["client_secret"], Username: str("username"), Password: r.Secrets["password"]}
	if st.IntegrationID == "" {
		_, st.IntegrationID, _ = integrations.LogicalID(r.Key)
	}
	need := func(what, v string) error {
		if v == "" {
			return fmt.Errorf("%w: %s is not set", errSettings, what)
		}
		return nil
	}
	switch r.System {
	case integrations.SystemSalesforce:
		st.Base, st.Auth, st.APIVersion = strings.TrimRight(str("instance_url"), "/"), str("auth_flow"), str("api_version")
		st.Audience, st.PrivateKeyPEM = str("audience"), r.Secrets["private_key_pem"]
		if st.Auth == "" {
			st.Auth = "client_credentials"
		}
		if st.APIVersion == "" {
			st.APIVersion = "62.0"
		}
		if st.Audience == "" {
			st.Audience = "https://login.salesforce.com"
		}
		st.TokenURL = st.Base + "/services/oauth2/token"
		if st.Auth == "jwt_bearer" {
			if err := need("the private key", st.PrivateKeyPEM); err != nil {
				return st, err
			}
			return st, need("the username", st.Username)
		}
		return st, need("the consumer secret", st.ClientSecret)
	case integrations.SystemServiceNow:
		st.Base, st.Auth, st.Tables = strings.TrimRight(str("instance_url"), "/"), str("auth_type"), list("test_tables")
		if st.Auth == "" {
			st.Auth = "basic"
		}
		if len(st.Tables) == 0 {
			st.Tables = []string{"incident"}
		}
		st.TokenURL = st.Base + "/oauth_token.do"
		if st.Auth == "basic" {
			if err := need("the user name", st.Username); err != nil {
				return st, err
			}
			return st, need("the password", st.Password)
		}
		if err := need("the client ID", st.ClientID); err != nil {
			return st, err
		}
		return st, need("the client secret", st.ClientSecret)
	case integrations.SystemSAP:
		st.Base, st.Auth, st.Services = strings.TrimRight(str("api_base_url"), "/"), str("auth_type"), list("services")
		st.TokenURL, st.Scope, st.SAPClient, st.Product = str("token_url"), str("scope"), str("sap_client"), str("product")
		if st.Auth == "" {
			st.Auth = "basic"
		}
		if len(st.Services) == 0 {
			st.Services = []string{"/sap/opu/odata/sap/API_BUSINESS_PARTNER"}
		}
		if st.Auth == "basic" {
			if err := need("the user name", st.Username); err != nil {
				return st, err
			}
			return st, need("the password", st.Password)
		}
		for what, v := range map[string]string{"the token URL": st.TokenURL, "the client ID": st.ClientID, "the client secret": st.ClientSecret} {
			if err := need(what, v); err != nil {
				return st, err
			}
		}
		return st, nil
	}
	return st, fmt.Errorf("%w: %s is not a REST connection type", errSettings, r.System)
}

// authError is a refusal by the provider's authentication (bad credentials,
// a disabled client, an unauthorized user).
type authError struct {
	status int
	detail string
}

func (e *authError) Error() string { return e.detail }

// token is a cached Authorization header value.
type token struct {
	header  string
	expires time.Time
	version time.Time
	ident   map[string]any // identity the token response revealed (Salesforce: org and user ids)
}

// authenticate returns the Authorization header for st (a fresh token).
func (s *Service) authenticate(ctx context.Context, st Settings) (token, error) {
	switch st.Auth {
	case "basic":
		return token{header: "Basic " + base64.StdEncoding.EncodeToString([]byte(st.Username+":"+st.Password)), expires: time.Now().Add(24 * time.Hour)}, nil
	case "client_credentials", "oauth_client_credentials":
		form := url.Values{"grant_type": {"client_credentials"}, "client_id": {st.ClientID}, "client_secret": {st.ClientSecret}}
		if st.Scope != "" {
			form.Set("scope", st.Scope)
		}
		return s.tokenRequest(ctx, st, form)
	case "jwt_bearer":
		assertion, err := salesforceJWT(st)
		if err != nil {
			return token{}, fmt.Errorf("%w: %v", errSettings, err)
		}
		return s.tokenRequest(ctx, st, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {assertion}})
	}
	return token{}, fmt.Errorf("%w: unsupported authentication %q", errSettings, clip(st.Auth, 40))
}

// tokenRequest POSTs an OAuth 2.0 token request (client authentication in
// the body, as Salesforce, ServiceNow and SAP all accept).
func (s *Service) tokenRequest(ctx context.Context, st Settings, form url.Values) (token, error) {
	if r := s.guard.Refused(st.System, st.TokenURL); r != "" {
		return token{}, &refusedURL{what: "token URL", reason: r}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, st.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return token{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := s.http.Do(req)
	if err != nil {
		return token{}, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var tr struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		ID          string `json:"id"` // Salesforce identity URL: .../id/<org>/<user>
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	_ = json.Unmarshal(b, &tr)
	if resp.StatusCode != http.StatusOK || tr.AccessToken == "" {
		msg := strings.TrimSpace(tr.Error + ": " + tr.Description)
		if tr.Error == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		if resp.StatusCode >= 500 {
			return token{}, fmt.Errorf("token endpoint answered HTTP %d", resp.StatusCode)
		}
		return token{}, &authError{status: resp.StatusCode, detail: "token request refused: " + clip(msg, 200)}
	}
	exp := time.Duration(tr.ExpiresIn) * time.Second
	if tr.ExpiresIn <= 0 || exp > 12*time.Hour {
		exp = 30 * time.Minute // Salesforce omits expires_in; its sessions last longer
	}
	t := token{header: "Bearer " + tr.AccessToken, expires: time.Now().Add(exp - time.Minute)}
	if parts := strings.Split(strings.TrimRight(tr.ID, "/"), "/"); len(parts) >= 2 && strings.Contains(tr.ID, "/id/") {
		t.ident = map[string]any{"organization_id": parts[len(parts)-2], "user_id": parts[len(parts)-1]}
	}
	return t, nil
}

// salesforceJWT builds the JWT bearer assertion (RS256; iss = consumer key,
// sub = username, aud = login URL, exp within 3 minutes).
func salesforceJWT(st Settings) (string, error) {
	key, err := parseRSAKey(st.PrivateKeyPEM)
	if err != nil {
		return "", err
	}
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	signing := enc(map[string]string{"alg": "RS256", "typ": "JWT"}) + "." +
		enc(map[string]any{"iss": st.ClientID, "sub": st.Username, "aud": st.Audience, "exp": time.Now().Add(3 * time.Minute).Unix()})
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func parseRSAKey(p string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(p))
	if block == nil {
		return nil, errors.New("the private key is not PEM")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("the private key could not be parsed")
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("the private key is not an RSA key")
	}
	return rk, nil
}

// refusedURL: the guard refused a URL before anything was sent.
type refusedURL struct{ what, reason string }

func (e *refusedURL) Error() string { return e.what + " not permitted: " + e.reason }

// probeResult is what one live check learned.
type probeResult struct {
	state        string
	detail       string
	httpStatus   int
	identity     map[string]any
	capabilities map[string]any
}

// get performs one authenticated read for a probe.
func (s *Service) get(ctx context.Context, st Settings, auth, path string, accept string) (int, []byte, error) {
	u := st.Base + path
	if r := s.guard.Refused(st.System, u); r != "" {
		return 0, nil, &refusedURL{what: "API URL", reason: r}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Accept", accept)
	resp, err := s.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp.StatusCode, b, nil
}

// statusState maps the HTTP status of a probe that failed.
func statusState(code int) string {
	switch code {
	case http.StatusUnauthorized:
		return StateAuthFailed
	case http.StatusForbidden:
		return StatePermission
	case http.StatusNotFound:
		return StateNotFound
	}
	return StateUnavailable
}

// --- Salesforce -----------------------------------------------------------

var sfObjects = []string{"Account", "Contact", "Lead", "Opportunity", "Case"}

func (s *Service) probeSalesforce(ctx context.Context, st Settings, t token) probeResult {
	res := probeResult{identity: map[string]any{}, capabilities: map[string]any{}}
	for k, v := range t.ident {
		res.identity[k] = v
	}
	code, b, err := s.get(ctx, st, t.header, "/services/data/", "application/json")
	if err != nil {
		return failure(err)
	}
	if code != http.StatusOK {
		res.state, res.httpStatus, res.detail = statusState(code), code, "GET /services/data/: "+sfError(code, b)
		return res
	}
	var versions []struct {
		Version string `json:"version"`
	}
	_ = json.Unmarshal(b, &versions)
	var vs []string
	for _, v := range versions {
		vs = append(vs, v.Version)
	}
	res.capabilities["api_versions_latest"] = lastN(vs, 3)
	if len(vs) > 0 && !contains(vs, st.APIVersion) {
		res.state, res.detail = StateNotFound, fmt.Sprintf("API version %s is not offered by this org (latest %s)", st.APIVersion, vs[len(vs)-1])
		return res
	}
	base := "/services/data/v" + st.APIVersion
	code, b, err = s.get(ctx, st, t.header, base+"/sobjects", "application/json")
	if err != nil {
		return failure(err)
	}
	if code != http.StatusOK {
		res.state, res.httpStatus, res.detail = statusState(code), code, "GET "+base+"/sobjects: "+sfError(code, b)
		return res
	}
	var desc struct {
		SObjects []struct {
			Name       string `json:"name"`
			Queryable  bool   `json:"queryable"`
			Createable bool   `json:"createable"`
			Updateable bool   `json:"updateable"`
			Deletable  bool   `json:"deletable"`
		} `json:"sobjects"`
	}
	_ = json.Unmarshal(b, &desc)
	objects := map[string]any{}
	queryable := 0
	for _, o := range desc.SObjects {
		if o.Queryable {
			queryable++
		}
		if contains(sfObjects, o.Name) {
			objects[o.Name] = map[string]bool{"read": o.Queryable, "create": o.Createable, "update": o.Updateable, "delete": o.Deletable}
		}
	}
	res.capabilities["objects_visible"] = len(desc.SObjects)
	res.capabilities["objects_queryable"] = queryable
	res.capabilities["common_objects"] = objects
	// API usage left, when the user may see it (needs View Setup; optional).
	if code, b, err = s.get(ctx, st, t.header, base+"/limits", "application/json"); err == nil && code == http.StatusOK {
		var lim map[string]struct{ Max, Remaining int }
		if json.Unmarshal(b, &lim) == nil {
			if d, ok := lim["DailyApiRequests"]; ok {
				res.capabilities["daily_api_requests"] = map[string]int{"max": d.Max, "remaining": d.Remaining}
			}
		}
	}
	res.state = StateConnected
	res.detail = fmt.Sprintf("token issued (%s); API v%s; %d objects visible, %d queryable", st.Auth, st.APIVersion, len(desc.SObjects), queryable)
	return res
}

func sfError(code int, b []byte) string {
	var errs []struct {
		ErrorCode string `json:"errorCode"`
		Message   string `json:"message"`
	}
	if json.Unmarshal(b, &errs) == nil && len(errs) > 0 {
		return fmt.Sprintf("HTTP %d %s: %s", code, clip(errs[0].ErrorCode, 60), clip(errs[0].Message, 160))
	}
	return fmt.Sprintf("HTTP %d", code)
}

// --- ServiceNow ------------------------------------------------------------

func (s *Service) probeServiceNow(ctx context.Context, st Settings, t token) probeResult {
	res := probeResult{identity: map[string]any{}, capabilities: map[string]any{}}
	if st.Auth == "basic" {
		res.identity["user_name"] = st.Username
	}
	tables := map[string]string{}
	readable, lastCode := 0, 0
	for _, tbl := range st.Tables {
		code, b, err := s.get(ctx, st, t.header, "/api/now/table/"+url.PathEscape(tbl)+"?sysparm_limit=1&sysparm_fields=sys_id", "application/json")
		if err != nil {
			return failure(err)
		}
		switch {
		case code == http.StatusOK:
			tables[tbl], readable = "readable", readable+1
		case code == http.StatusUnauthorized:
			res.state, res.httpStatus, res.detail = StateAuthFailed, code, "the instance refused the credentials: "+snError(code, b)
			return res
		case code == http.StatusForbidden:
			tables[tbl] = "no read access (ACL)"
		case code == http.StatusBadRequest || code == http.StatusNotFound:
			tables[tbl] = "not found"
		default:
			tables[tbl] = fmt.Sprintf("HTTP %d", code)
		}
		lastCode = code
	}
	res.capabilities["tables"] = tables
	if readable == 0 {
		res.state, res.httpStatus = statusState(lastCode), lastCode
		if lastCode == http.StatusBadRequest {
			res.state = StateNotFound
		}
		res.detail = "authenticated, but none of the tables checked is readable: " + summarize(tables)
		return res
	}
	res.state = StateConnected
	res.detail = fmt.Sprintf("authenticated (%s); %d of %d tables readable: %s", st.Auth, readable, len(st.Tables), summarize(tables))
	return res
}

func snError(code int, b []byte) string {
	var e struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(b, &e) == nil && e.Error.Message != "" {
		return fmt.Sprintf("HTTP %d: %s", code, clip(e.Error.Message, 160))
	}
	return fmt.Sprintf("HTTP %d", code)
}

// --- SAP -------------------------------------------------------------------

var entitySetRe = regexp.MustCompile(`<EntitySet\s+[^>]*Name="([A-Za-z0-9_]{1,128})"`)

func (s *Service) probeSAP(ctx context.Context, st Settings, t token) probeResult {
	res := probeResult{identity: map[string]any{}, capabilities: map[string]any{}}
	if st.Auth == "basic" {
		res.identity["user_name"] = st.Username
	}
	services := map[string]any{}
	ok, lastCode := 0, 0
	for _, svc := range st.Services {
		path := strings.TrimRight(svc, "/") + "/$metadata"
		if st.SAPClient != "" {
			path += "?sap-client=" + url.QueryEscape(st.SAPClient)
		}
		code, b, err := s.get(ctx, st, t.header, path, "application/xml")
		if err != nil {
			return failure(err)
		}
		lastCode = code
		switch code {
		case http.StatusOK:
			var sets []string
			for _, m := range entitySetRe.FindAllSubmatch(b, 500) {
				sets = append(sets, string(m[1]))
			}
			sort.Strings(sets)
			services[svc] = map[string]any{"entity_sets": len(sets), "sample": firstN(sets, 12)}
			ok++
		case http.StatusUnauthorized:
			res.state, res.httpStatus, res.detail = StateAuthFailed, code, "the system refused the credentials (HTTP 401)"
			return res
		case http.StatusForbidden:
			services[svc] = "not authorized (check the communication arrangement or roles)"
		case http.StatusNotFound:
			services[svc] = "not found (service not exposed or not activated)"
		default:
			services[svc] = fmt.Sprintf("HTTP %d", code)
		}
	}
	res.capabilities["services"] = services
	if st.Product != "" {
		res.capabilities["product"] = st.Product
	}
	if ok == 0 {
		res.state, res.httpStatus = statusState(lastCode), lastCode
		res.detail = "none of the OData services checked returned its $metadata"
		return res
	}
	res.state = StateConnected
	res.detail = fmt.Sprintf("authenticated (%s); %d of %d OData services readable", st.Auth, ok, len(st.Services))
	return res
}

// --- helpers ----------------------------------------------------------------

func failure(err error) probeResult {
	var ref *refusedURL
	if errors.As(err, &ref) || refusedErr(err) {
		return probeResult{state: StateNotPermitted, detail: err.Error()}
	}
	return probeResult{state: StateUnavailable, detail: "unreachable: " + clip(err.Error(), 200)}
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func lastN(list []string, n int) []string {
	if len(list) <= n {
		return list
	}
	return list[len(list)-n:]
}

func firstN(list []string, n int) []string {
	if len(list) <= n {
		return list
	}
	return list[:n]
}

func summarize(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+": "+m[k])
	}
	return strings.Join(parts, "; ")
}
