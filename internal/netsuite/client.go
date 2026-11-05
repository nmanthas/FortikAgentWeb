// Package netsuite is Fortik's NetSuite integration (Milestone 1).
//
// What it does, and how sure we are (docs/INTEGRATION_MILESTONES.md §M1):
//
//   - Fortik authenticates to NetSuite with OAuth 2.0 client credentials
//     (machine to machine): a JWT signed with the private key of a
//     certificate uploaded to NetSuite's client-credentials setup, exchanged
//     at the account's token endpoint for a 60-minute access token. The token
//     is held by Fortik and never given to an agent.
//   - Agents call NetSuite's REST web services THROUGH Fortik's app gateway
//     (/gw/netsuite/services/rest/...): every record read, create, update,
//     delete and SuiteQL query is mapped to an Action and decided before it
//     is forwarded (pre-execution enforcement, but only for traffic routed
//     through Fortik).
//   - Updates are snapshotted first (the changed fields' previous values,
//     encrypted in Fortik's secret store) so they can be undone.
//   - Activity made OUTSIDE Fortik is read afterwards from the account's
//     audit data with SuiteQL (system notes), evaluated by policy and
//     recorded as observed after execution (detection, never prevention).
//
// Everything here follows NetSuite's documented REST web services, OAuth 2.0
// and SuiteQL interfaces. As of 2026-10-25 it has been exercised only against
// a local fake (internal/netsuite/fakens): no NetSuite account was available.
// The connector probes the real account on Test/Health and reports which
// capabilities actually work there, instead of assuming them.
package netsuite

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
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
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"fortik/internal/integrations"
)

// IntegrationKey is the integrations key (console > Integrations).
const IntegrationKey = integrations.SystemNetSuite

// System is the Fortik action system for NetSuite operations.
const System = "netsuite"

const (
	assertionType  = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	tokenPath      = "/services/rest/auth/oauth2/v1/token"
	suiteqlPath    = "/services/rest/query/v1/suiteql"
	maxResponse    = 32 << 20
	defaultScope   = "rest_webservices"
	assertionTTL   = 5 * time.Minute
	tokenSkew      = 2 * time.Minute
	requestTimeout = 30 * time.Second
)

// ErrNotConfigured: the integration is missing (the gateway answers 503).
var ErrNotConfigured = integrations.ErrNotConfigured

var accountRe = regexp.MustCompile(`^[A-Za-z0-9]+(_[A-Za-z0-9]+)?$`)

// Settings is the integration's configuration (secrets resolved in-process).
type Settings struct {
	Key           string // the connection key: netsuite or netsuite:<tenant>
	IntegrationID string // the logical integration, e.g. netsuite:acme
	AccountID     string // e.g. 1234567 or 1234567_SB1
	ClientID      string // the integration record's client ID (consumer key)
	CertificateID string // the certificate id NetSuite assigned on upload (JWT kid)
	Algorithm     string // PS256 (RSA) or ES256 (EC P-256)
	Scope         string // rest_webservices (default)
	APIBase       string // optional override, e.g. a test endpoint; default https://<account>.suitetalk.api.netsuite.com
	PrivateKeyPEM string // secret
	ActivityQuery string // optional SuiteQL override for the audit data (see activity.go)
	AgentMap      map[string]string
}

// SettingsFrom reads the integration.
func SettingsFrom(r integrations.Resolved) (Settings, error) {
	s := Settings{Key: r.Key, IntegrationID: r.IntegrationID, AccountID: r.Text("account_id"), ClientID: r.Text("client_id"), CertificateID: r.Text("certificate_id"),
		Algorithm: strings.ToUpper(r.Text("algorithm")), Scope: r.Text("scope"), APIBase: strings.TrimRight(r.Text("api_base"), "/"),
		PrivateKeyPEM: r.Secret("private_key_pem"), ActivityQuery: r.Text("activity_query"), AgentMap: map[string]string{}}
	if s.Algorithm == "" {
		s.Algorithm = "PS256"
	}
	if s.Scope == "" {
		s.Scope = defaultScope
	}
	for _, m := range r.Strings("agent_map") {
		fa, ne, ok := strings.Cut(m, "=")
		if ok && strings.TrimSpace(fa) != "" && strings.TrimSpace(ne) != "" {
			s.AgentMap[strings.TrimSpace(fa)] = strings.TrimSpace(ne)
		}
	}
	switch {
	case !accountRe.MatchString(s.AccountID):
		return s, errors.New("netsuite: account_id must look like 1234567 or 1234567_SB1")
	case s.ClientID == "" || s.CertificateID == "":
		return s, errors.New("netsuite: client_id and certificate_id are required")
	case s.PrivateKeyPEM == "":
		return s, fmt.Errorf("%w: netsuite private key", integrations.ErrSecretMissing)
	}
	return s, nil
}

// BaseURL is the account's REST host: the account id lower-cased with "_"
// as "-" (NetSuite's account-specific domain), unless APIBase overrides it.
func (s Settings) BaseURL() string {
	if s.APIBase != "" {
		return s.APIBase
	}
	return "https://" + strings.ReplaceAll(strings.ToLower(s.AccountID), "_", "-") + ".suitetalk.api.netsuite.com"
}

// TokenURL is the account's OAuth 2.0 token endpoint (also the JWT audience).
func (s Settings) TokenURL() string { return s.BaseURL() + tokenPath }

// Client talks to one NetSuite account with a cached Fortik-held token.
type Client struct {
	http *http.Client
	now  func() time.Time

	mu    sync.Mutex
	cache map[string]cachedToken // key: account|client|cert
}

type cachedToken struct {
	token string
	exp   time.Time
}

// NewClient returns a client (nil = default http client with a timeout).
func NewClient(hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: requestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	return &Client{http: hc, now: time.Now, cache: map[string]cachedToken{}}
}

// Token returns a valid access token, minting one when needed.
func (c *Client) Token(ctx context.Context, s Settings) (string, error) {
	key := s.AccountID + "|" + s.ClientID + "|" + s.CertificateID
	c.mu.Lock()
	if t, ok := c.cache[key]; ok && c.now().Add(tokenSkew).Before(t.exp) {
		c.mu.Unlock()
		return t.token, nil
	}
	c.mu.Unlock()
	assertion, err := signAssertion(s, c.now())
	if err != nil {
		return "", err
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_assertion_type": {assertionType}, "client_assertion": {assertion}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.TokenURL(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("netsuite token: %s", redact(err.Error()))
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("netsuite token: HTTP %d: %s", res.StatusCode, clip(oauthError(b), 200))
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   any    `json:"expires_in"`
	}
	if err := json.Unmarshal(b, &tr); err != nil || tr.AccessToken == "" {
		return "", errors.New("netsuite token: malformed token response")
	}
	exp := c.now().Add(time.Duration(seconds(tr.ExpiresIn)) * time.Second)
	c.mu.Lock()
	c.cache[key] = cachedToken{token: tr.AccessToken, exp: exp}
	c.mu.Unlock()
	return tr.AccessToken, nil
}

// Drop forgets every cached token (kill / disable): the next call mints anew.
func (c *Client) Drop() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(c.cache)
	c.cache = map[string]cachedToken{}
	return n
}

// Do performs an authenticated request; path must start with /services/.
func (c *Client) Do(ctx context.Context, s Settings, method, path, rawQuery string, body []byte, hdr http.Header) (*http.Response, []byte, error) {
	if !strings.HasPrefix(path, "/services/rest/") {
		return nil, nil, fmt.Errorf("netsuite: refusing a path outside /services/rest/: %q", clip(path, 80))
	}
	tok, err := c.Token(ctx, s)
	if err != nil {
		return nil, nil, err
	}
	u := s.BaseURL() + path
	if rawQuery != "" {
		u += "?" + rawQuery
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, nil, err
	}
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if body != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("netsuite %s %s: %s", method, clip(path, 80), redact(err.Error()))
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, maxResponse+1))
	if err != nil {
		return nil, nil, err
	}
	if len(b) > maxResponse {
		return nil, nil, errors.New("netsuite: response exceeds the gateway limit")
	}
	return res, b, nil
}

// SuiteQL runs one query page (NetSuite pages at most 1000 rows).
func (c *Client) SuiteQL(ctx context.Context, s Settings, q string, limit, offset int) ([]map[string]any, bool, error) {
	body, _ := json.Marshal(map[string]string{"q": q})
	qs := url.Values{"limit": {fmt.Sprint(limit)}, "offset": {fmt.Sprint(offset)}}
	res, b, err := c.Do(ctx, s, http.MethodPost, suiteqlPath, qs.Encode(), body, http.Header{"Prefer": {"transient"}})
	if err != nil {
		return nil, false, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("suiteql: HTTP %d: %s", res.StatusCode, clip(nsError(b), 300))
	}
	var out struct {
		Items   []map[string]any `json:"items"`
		HasMore bool             `json:"hasMore"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, false, errors.New("suiteql: malformed response")
	}
	return out.Items, out.HasMore, nil
}

// signAssertion builds the client-credentials JWT: header {alg, typ, kid =
// certificate id}; claims {iss = client id, scope, aud = token URL, iat, exp}.
func signAssertion(s Settings, now time.Time) (string, error) {
	block, _ := pem.Decode([]byte(s.PrivateKeyPEM))
	if block == nil {
		return "", errors.New("netsuite: private key is not PEM")
	}
	key, err := parseKey(block.Bytes)
	if err != nil {
		return "", err
	}
	hdr, _ := json.Marshal(map[string]string{"alg": s.Algorithm, "typ": "JWT", "kid": s.CertificateID})
	claims, _ := json.Marshal(map[string]any{"iss": s.ClientID, "scope": strings.Split(s.Scope, ","), "aud": s.TokenURL(),
		"iat": now.Unix(), "exp": now.Add(assertionTTL).Unix()})
	input := b64(hdr) + "." + b64(claims)
	sum := sha256.Sum256([]byte(input))
	var sig []byte
	switch s.Algorithm {
	case "PS256":
		k, ok := key.(*rsa.PrivateKey)
		if !ok {
			return "", errors.New("netsuite: PS256 needs an RSA private key")
		}
		sig, err = rsa.SignPSS(rand.Reader, k, crypto.SHA256, sum[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	case "ES256":
		k, ok := key.(*ecdsa.PrivateKey)
		if !ok || k.Curve.Params().BitSize != 256 {
			return "", errors.New("netsuite: ES256 needs an EC P-256 private key")
		}
		var r, ss *big.Int
		r, ss, err = ecdsa.Sign(rand.Reader, k, sum[:])
		if err == nil {
			sig = make([]byte, 64)
			r.FillBytes(sig[:32])
			ss.FillBytes(sig[32:])
		}
	default:
		return "", fmt.Errorf("netsuite: algorithm %q is not supported (PS256 or ES256)", s.Algorithm)
	}
	if err != nil {
		return "", fmt.Errorf("netsuite: sign assertion: %w", err)
	}
	return input + "." + b64(sig), nil
}

func parseKey(der []byte) (any, error) {
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	return nil, errors.New("netsuite: unsupported private key (PKCS#8, PKCS#1 RSA or SEC1 EC)")
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func seconds(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case string:
		var n int64
		_, _ = fmt.Sscan(x, &n)
		return n
	}
	return 0
}

var bearerRe = regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._~+/=-]+`)

func redact(s string) string { return bearerRe.ReplaceAllString(s, "Bearer [redacted]") }

func oauthError(b []byte) string {
	var e struct {
		Error string `json:"error"`
		Desc  string `json:"error_description"`
	}
	if json.Unmarshal(b, &e) == nil && e.Error != "" {
		return strings.TrimSpace(e.Error + " " + e.Desc)
	}
	return "unexpected token response"
}

// nsError extracts NetSuite's REST error detail ({"o:errorDetails":[{"detail":...}]}).
func nsError(b []byte) string {
	var e struct {
		Title   string `json:"title"`
		Details []struct {
			Detail string `json:"detail"`
		} `json:"o:errorDetails"`
	}
	if json.Unmarshal(b, &e) == nil {
		if len(e.Details) > 0 && e.Details[0].Detail != "" {
			return e.Details[0].Detail
		}
		if e.Title != "" {
			return e.Title
		}
	}
	return "unexpected response"
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
