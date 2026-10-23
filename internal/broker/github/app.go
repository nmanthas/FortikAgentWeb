// Package github brokers GitHub App installation tokens, the only GitHub
// credential Fortik issues. It holds the GitHub App client shared by the
// direct-token broker adapter (this package) and the REST gateway adapter
// (internal/gateway/github): app JWTs, narrowed installation tokens and
// their revocation, the "github" integration tester, and access-profile
// helpers.
//
// Security properties:
//   - Every installation token is minted for exactly the repositories and
//     permissions asked for; GitHub's response is checked and a token that
//     grants more than requested is revoked and refused.
//   - Tokens and the app private key are never logged, stored in Postgres or
//     put in errors (Token implements fmt.Stringer and slog.LogValuer with
//     redaction).
//   - The API base URL must be https (plain http only to a loopback host, for
//     local fakes), so a token can never travel in clear text.
package github

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"fortik/internal/broker"
	"fortik/internal/integrations"
)

// System is the broker/action system name; IntegrationKey the integrations row.
const (
	System         = "github"
	IntegrationKey = "github"
	// DefaultBaseURL is used when the integration leaves api_base_url empty.
	DefaultBaseURL = "https://api.github.com"
	// APIVersion is the GitHub REST API version Fortik speaks.
	APIVersion = "2022-11-28"
)

// notConfigured matches both integrations.ErrNotConfigured and
// broker.ErrNotConfigured, so the gateway (503 integration_not_configured)
// and the broker core recognise it with errors.Is.
type notConfigured struct{ detail string }

func (e notConfigured) Error() string {
	if e.detail == "" {
		return "github: integration not configured"
	}
	return "github: integration not configured: " + e.detail
}

func (e notConfigured) Is(target error) bool {
	return target == integrations.ErrNotConfigured || target == broker.ErrNotConfigured
}

// ErrNotConfigured is returned (wrapped) when the "github" integration or its
// private key is missing. errors.Is(err, integrations.ErrNotConfigured) and
// errors.Is(err, broker.ErrNotConfigured) both hold.
var ErrNotConfigured error = notConfigured{}

// APIError is a non-2xx GitHub response. Message is GitHub's own error text
// (truncated); it never contains request credentials.
type APIError struct {
	Op      string
	Status  int
	Message string
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("github: %s: HTTP %d", e.Op, e.Status)
	}
	return fmt.Sprintf("github: %s: HTTP %d: %s", e.Op, e.Status, e.Message)
}

// Settings is the resolved "github" integration, ready for use. The private
// key stays unexported so it cannot be serialised by accident.
type Settings struct {
	BaseURL        string // no trailing slash
	AppID          string
	InstallationID string
	key            *rsa.PrivateKey
	// Fingerprint identifies the settings (base URL, app, installation and a
	// hash prefix of the key) for cache keys. Not secret.
	Fingerprint string
}

// Token is a minted installation token. Secret must never leave Fortik in
// gateway mode and is never logged: String, LogValue and MarshalJSON redact it.
type Token struct {
	Secret      string            `json:"-"`
	ExpiresAt   time.Time         `json:"expires_at"`
	Repos       []string          `json:"repositories"` // repository names (no owner), as granted
	Permissions map[string]string `json:"permissions"`  // as granted
	BaseURL     string            `json:"-"`
}

func (t Token) String() string {
	return fmt.Sprintf("github installation token [redacted] (repos=%v, permissions=%v, expires=%s)",
		t.Repos, t.Permissions, t.ExpiresAt.UTC().Format(time.RFC3339))
}

// LogValue keeps the secret out of structured logs.
func (t Token) LogValue() slog.Value {
	return slog.GroupValue(slog.Any("repositories", t.Repos), slog.Any("permissions", t.Permissions),
		slog.Time("expires_at", t.ExpiresAt), slog.String("token", "[redacted]"))
}

// Installation is the subset of GET /app/installations/{id} Fortik uses.
type Installation struct {
	ID          int64             `json:"id"`
	Account     string            `json:"-"` // account.login: the owner every repo must belong to
	Permissions map[string]string `json:"permissions"`
}

// Client talks to the GitHub App API. It is safe for concurrent use.
type Client struct {
	HTTP *http.Client
	Now  func() time.Time

	keyMu   sync.Mutex
	keyHash [32]byte
	key     *rsa.PrivateKey

	instMu sync.Mutex
	inst   map[string]cachedInstallation // by Settings.Fingerprint
}

type cachedInstallation struct {
	inst Installation
	at   time.Time
}

// installationTTL bounds how long the installation account is cached.
const installationTTL = 5 * time.Minute

// NewClient returns a client. A nil hc gets a client with a 30 s timeout that
// never follows redirects (a redirect must never carry a token elsewhere).
func NewClient(hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	c := *hc
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{HTTP: &c, inst: map[string]cachedInstallation{}}
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

var digits = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)

// Settings validates a resolved integration. Missing required values yield
// ErrNotConfigured; malformed ones integrations.ErrInvalid.
func (c *Client) Settings(r integrations.Resolved) (Settings, error) {
	base := strings.TrimRight(strings.TrimSpace(stringOf(r.ConfigMap["api_base_url"])), "/")
	if base == "" {
		base = DefaultBaseURL
	}
	if err := checkBaseURL(base); err != nil {
		return Settings{}, err
	}
	appID := stringOf(r.ConfigMap["app_id"])
	instID := stringOf(r.ConfigMap["installation_id"])
	if appID == "" || instID == "" {
		return Settings{}, notConfigured{detail: "app_id and installation_id are required"}
	}
	if !digits.MatchString(appID) || !digits.MatchString(instID) {
		return Settings{}, fmt.Errorf("%w: github app_id and installation_id must be positive integers", integrations.ErrInvalid)
	}
	pemText := r.Secrets["private_key_pem"]
	if strings.TrimSpace(pemText) == "" {
		return Settings{}, notConfigured{detail: "private_key_pem is not set"}
	}
	key, hash, err := c.parseKey(pemText)
	if err != nil {
		return Settings{}, err
	}
	fp := sha256.Sum256([]byte(base + "\x00" + appID + "\x00" + instID + "\x00" + hex.EncodeToString(hash[:])))
	return Settings{BaseURL: base, AppID: appID, InstallationID: instID, key: key, Fingerprint: hex.EncodeToString(fp[:8])}, nil
}

// checkBaseURL refuses anything but https, except http to a loopback host
// (local fakes in tests and dev).
func checkBaseURL(base string) error {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%w: github api_base_url must be an absolute URL without credentials, query or fragment", integrations.ErrInvalid)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return fmt.Errorf("%w: github api_base_url must use https (http is allowed only for loopback test fakes)", integrations.ErrInvalid)
}

func (c *Client) parseKey(pemText string) (*rsa.PrivateKey, [32]byte, error) {
	h := sha256.Sum256([]byte(pemText))
	c.keyMu.Lock()
	defer c.keyMu.Unlock()
	if c.key != nil && c.keyHash == h {
		return c.key, h, nil
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(pemText))
	if err != nil {
		// Never echo the parser's view of the input.
		return nil, h, fmt.Errorf("%w: github private_key_pem is not a valid RSA private key (PKCS#1 or PKCS#8 PEM)", integrations.ErrInvalid)
	}
	c.key, c.keyHash = key, h
	return key, h, nil
}

// AppJWT signs the GitHub App JWT: RS256, iss = app id, iat = now-60s (clock
// drift allowance, as GitHub recommends), exp = now+9m (GitHub's limit is 10m).
func (c *Client) AppJWT(s Settings) (string, error) {
	if s.key == nil {
		return "", ErrNotConfigured
	}
	now := c.now()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		Issuer:    s.AppID,
		IssuedAt:  jwt.NewNumericDate(now.Add(-60 * time.Second)),
		ExpiresAt: jwt.NewNumericDate(now.Add(9 * time.Minute)),
	})
	signed, err := tok.SignedString(s.key)
	if err != nil {
		return "", errors.New("github: could not sign the app JWT")
	}
	return signed, nil
}

// Installation returns the installation (account login and permissions),
// cached for a few minutes per settings.
func (c *Client) Installation(ctx context.Context, s Settings) (Installation, error) {
	c.instMu.Lock()
	ci, ok := c.inst[s.Fingerprint]
	c.instMu.Unlock()
	if ok && c.now().Sub(ci.at) < installationTTL {
		return ci.inst, nil
	}
	appJWT, err := c.AppJWT(s)
	if err != nil {
		return Installation{}, err
	}
	var raw struct {
		ID      int64 `json:"id"`
		Account struct {
			Login string `json:"login"`
		} `json:"account"`
		Permissions map[string]string `json:"permissions"`
	}
	if _, err := c.JSON(ctx, s.BaseURL, appJWT, http.MethodGet, "/app/installations/"+s.InstallationID, nil, &raw, "get installation", http.StatusOK); err != nil {
		return Installation{}, err
	}
	if raw.Account.Login == "" {
		return Installation{}, errors.New("github: installation has no account login")
	}
	inst := Installation{ID: raw.ID, Account: raw.Account.Login, Permissions: raw.Permissions}
	c.instMu.Lock()
	c.inst[s.Fingerprint] = cachedInstallation{inst: inst, at: c.now()}
	c.instMu.Unlock()
	return inst, nil
}

// ErrWrongOwner: the repository does not belong to the installation's account,
// so no installation token can (or may) be scoped to it.
var ErrWrongOwner = errors.New("github: repository owner is not the account of the configured app installation")

// CheckOwner verifies that owner is the installation's account. Installation
// tokens name repositories without an owner, so this check is what binds a
// token to "owner/name" and not to a same-named repository elsewhere.
func (c *Client) CheckOwner(ctx context.Context, s Settings, owner string) error {
	inst, err := c.Installation(ctx, s)
	if err != nil {
		return err
	}
	if !strings.EqualFold(inst.Account, owner) {
		return fmt.Errorf("%w (%s)", ErrWrongOwner, owner)
	}
	return nil
}

// MintToken mints an installation token for exactly repoNames (names without
// owner; empty = permissions-only token used by the tester) and perms. The
// response is verified: a token granting more than asked is revoked and refused.
func (c *Client) MintToken(ctx context.Context, s Settings, repoNames []string, perms map[string]string) (Token, error) {
	if len(perms) == 0 {
		return Token{}, errors.New("github: refusing to mint a token without explicit permissions (GitHub would grant all installation permissions)")
	}
	for k, v := range perms {
		if !validPermName.MatchString(k) || levelRank(v) == 0 {
			return Token{}, fmt.Errorf("github: invalid permission %q:%q", k, v)
		}
	}
	appJWT, err := c.AppJWT(s)
	if err != nil {
		return Token{}, err
	}
	body := map[string]any{"permissions": perms}
	if len(repoNames) > 0 {
		body["repositories"] = repoNames
	}
	var resp struct {
		Token        string            `json:"token"`
		ExpiresAt    time.Time         `json:"expires_at"`
		Permissions  map[string]string `json:"permissions"`
		Repositories []struct {
			Name string `json:"name"`
		} `json:"repositories"`
		RepositorySelection string `json:"repository_selection"`
	}
	if _, err := c.JSON(ctx, s.BaseURL, appJWT, http.MethodPost, "/app/installations/"+s.InstallationID+"/access_tokens", body, &resp,
		"mint installation token", http.StatusCreated); err != nil {
		return Token{}, err
	}
	if resp.Token == "" || resp.ExpiresAt.IsZero() {
		return Token{}, errors.New("github: installation token response is missing token or expires_at")
	}
	tok := Token{Secret: resp.Token, ExpiresAt: resp.ExpiresAt, Permissions: resp.Permissions, BaseURL: s.BaseURL}
	for _, r := range resp.Repositories {
		tok.Repos = append(tok.Repos, r.Name)
	}
	if err := verifyGrant(repoNames, perms, tok, resp.RepositorySelection); err != nil {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		_ = c.RevokeToken(rctx, s.BaseURL, tok.Secret)
		return Token{}, err
	}
	return tok, nil
}

// verifyGrant checks GitHub granted no more than requested.
func verifyGrant(repoNames []string, perms map[string]string, tok Token, selection string) error {
	if len(repoNames) > 0 {
		if selection == "all" {
			return errors.New("github: token was granted all repositories though specific ones were requested; revoked")
		}
		want := map[string]bool{}
		for _, n := range repoNames {
			want[strings.ToLower(n)] = true
		}
		for _, n := range tok.Repos {
			if !want[strings.ToLower(n)] {
				return fmt.Errorf("github: token was granted unrequested repository %q; revoked", n)
			}
		}
	}
	for k, v := range tok.Permissions {
		if levelRank(v) > levelRank(perms[k]) {
			return fmt.Errorf("github: token was granted %s:%s beyond the requested %q; revoked", k, v, perms[k])
		}
	}
	return nil
}

// RevokeToken revokes an installation token (DELETE /installation/token).
// A token that is already invalid (401) counts as revoked.
func (c *Client) RevokeToken(ctx context.Context, baseURL, token string) error {
	_, err := c.JSON(ctx, baseURL, token, http.MethodDelete, "/installation/token", nil, nil, "revoke installation token", http.StatusNoContent)
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusUnauthorized {
		return nil
	}
	return err
}

// JSON performs one request with bearer auth (an app JWT or an installation
// token), sends body as JSON when non-nil and decodes a JSON response into
// out when non-nil. A status not in ok yields *APIError.
func (c *Client) JSON(ctx context.Context, baseURL, bearer, method, path string, body, out any, op string, ok ...int) (int, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, baseURL+path, rd)
	if err != nil {
		return 0, fmt.Errorf("github: %s: build request: %w", op, err)
	}
	SetAPIHeaders(req.Header, bearer)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, fmt.Errorf("github: %s: %w", op, scrubURLError(err))
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return resp.StatusCode, fmt.Errorf("github: %s: read response: %w", op, err)
	}
	accepted := false
	for _, code := range ok {
		if resp.StatusCode == code {
			accepted = true
		}
	}
	if !accepted {
		return resp.StatusCode, &APIError{Op: op, Status: resp.StatusCode, Message: errorMessage(raw)}
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, fmt.Errorf("github: %s: decode response: %w", op, err)
		}
	}
	return resp.StatusCode, nil
}

// SetAPIHeaders sets the headers every Fortik → GitHub request carries.
func SetAPIHeaders(h http.Header, bearer string) {
	h.Set("Authorization", "Bearer "+bearer)
	h.Set("Accept", "application/vnd.github+json")
	h.Set("X-GitHub-Api-Version", APIVersion)
	h.Set("User-Agent", "fortik-authority-broker")
}

// scrubURLError drops the URL from transport errors (it never holds a token
// here, but keeping errors URL-free makes that a non-question).
func scrubURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s request failed: %w", ue.Op, ue.Err)
	}
	return err
}

func errorMessage(raw []byte) string {
	var e struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(raw, &e) == nil && e.Message != "" {
		return truncate(e.Message, 200)
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func stringOf(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
	case json.Number:
		return t.String()
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	}
	return ""
}

var validPermName = regexp.MustCompile(`^[a-z][a-z_]{0,63}$`)

// levelRank orders GitHub permission levels; 0 = none/unknown.
func levelRank(l string) int {
	switch l {
	case "read":
		return 1
	case "write":
		return 2
	case "admin":
		return 3
	}
	return 0
}

// LevelCovers reports whether level have includes want (write covers read).
func LevelCovers(have, want string) bool {
	return levelRank(want) > 0 && levelRank(have) >= levelRank(want)
}

// PermKey renders a permission set canonically (cache keys, scopes).
func PermKey(perms map[string]string) string {
	keys := make([]string, 0, len(perms))
	for k := range perms {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(k + ":" + perms[k])
	}
	return b.String()
}
