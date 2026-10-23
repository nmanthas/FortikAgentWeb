package google

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	googleoauth "golang.org/x/oauth2/google"
	"golang.org/x/sync/singleflight"

	"fortik/internal/action"
	"fortik/internal/broker"
)

// OAuth scopes, the minimum per endpoint (see scopesFor in map.go). The
// service account's domain-wide delegation must allow every scope used.
const (
	ScopeGmailReadonly        = "https://www.googleapis.com/auth/gmail.readonly"
	ScopeGmailSend            = "https://www.googleapis.com/auth/gmail.send"
	ScopeGmailCompose         = "https://www.googleapis.com/auth/gmail.compose"
	ScopeGmailModify          = "https://www.googleapis.com/auth/gmail.modify"
	ScopeGmailFull            = "https://mail.google.com/"
	ScopeGmailSettingsBasic   = "https://www.googleapis.com/auth/gmail.settings.basic"
	ScopeGmailSettingsSharing = "https://www.googleapis.com/auth/gmail.settings.sharing"
	ScopeDrive                = "https://www.googleapis.com/auth/drive"
	ScopeDriveReadonly        = "https://www.googleapis.com/auth/drive.readonly"
)

// RequiredScopes lists every scope the adapter may request; the Workspace
// admin authorises these for the service account's client id.
var RequiredScopes = []string{
	ScopeGmailReadonly, ScopeGmailSend, ScopeGmailCompose, ScopeGmailModify, ScopeGmailFull,
	ScopeGmailSettingsBasic, ScopeGmailSettingsSharing, ScopeDrive, ScopeDriveReadonly,
}

// DefaultTokenURL is Google's OAuth token endpoint. The token_uri inside a
// service account JSON is ignored: the endpoint comes from config only.
const DefaultTokenURL = googleoauth.JWTTokenURL

// IssuanceRecorder stores a gateway-held credential mint in
// credential_issuances and the Diary (broker.Broker satisfies it). The
// Credential passed never contains the token.
type IssuanceRecorder interface {
	RecordIssuance(ctx context.Context, c broker.Credential, agentID, instanceID string) error
}

// errMint marks a failure to obtain a Google access token.
var errMint = errors.New("could not obtain a Google access token")

// tokenMinter mints domain-wide-delegation access tokens and caches them per
// (agent, subject, service account, scope set) until a minute before expiry.
// Tokens never leave the gateway.
type tokenMinter struct {
	client   *http.Client
	tokenURL string
	rec      IssuanceRecorder
	now      func() time.Time

	mu    sync.Mutex
	cache map[string]cachedToken
	sf    singleflight.Group
}

type cachedToken struct {
	agentID string
	system  string // gmail | drive
	token   string
	expiry  time.Time
}

type mintRequest struct {
	agentID    string
	instanceID string
	actionID   string // the decided action that caused the mint (issuance record)
	subject    string // the Workspace user impersonated
	system     string // gmail | drive
	scopes     []string
}

const tokenEarlyExpiry = time.Minute

func newTokenMinter(client *http.Client, tokenURL string, rec IssuanceRecorder, now func() time.Time) *tokenMinter {
	if tokenURL == "" {
		tokenURL = DefaultTokenURL
	}
	return &tokenMinter{client: client, tokenURL: tokenURL, rec: rec, now: now, cache: map[string]cachedToken{}}
}

func (m *tokenMinter) key(s settings, req mintRequest) string {
	scopes := append([]string(nil), req.scopes...)
	sort.Strings(scopes)
	return strings.Join([]string{req.agentID, req.subject, s.fingerprint, strings.Join(scopes, " ")}, "\x00")
}

// token returns a cached or freshly minted access token.
func (m *tokenMinter) token(ctx context.Context, s settings, req mintRequest) (string, error) {
	if req.subject == "" || len(req.scopes) == 0 {
		return "", fmt.Errorf("%w: subject and scopes are required", errMint)
	}
	k := m.key(s, req)
	m.mu.Lock()
	if c, ok := m.cache[k]; ok && m.now().Before(c.expiry.Add(-tokenEarlyExpiry)) {
		m.mu.Unlock()
		return c.token, nil
	}
	m.mu.Unlock()
	v, err, _ := m.sf.Do(k, func() (any, error) {
		mctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		tok, err := mintDWD(mctx, m.client, m.tokenURL, s.saJSON, req.subject, req.scopes)
		if err != nil {
			return nil, err
		}
		if m.rec != nil {
			c := broker.Credential{
				IssuanceID: action.NewID("iss"), ActionID: req.actionID, System: req.system, ExpiresAt: tok.Expiry,
				Scope: map[string]any{"subject": req.subject, "scopes": req.scopes, "held_by": "gateway", "method": "google_dwd"},
			}
			if err := m.rec.RecordIssuance(mctx, c, req.agentID, req.instanceID); err != nil {
				// An unrecorded credential is never used.
				return nil, fmt.Errorf("%w: issuance could not be recorded: %v", errMint, err)
			}
		}
		if !tok.Expiry.IsZero() {
			m.mu.Lock()
			m.cache[k] = cachedToken{agentID: req.agentID, system: req.system, token: tok.AccessToken, expiry: tok.Expiry}
			m.mu.Unlock()
		}
		return tok.AccessToken, nil
	})
	if err != nil {
		return "", err
	}
	return v.(string), nil
}

// dropAgent forgets the cached tokens of an agent for one system ("" = all).
func (m *tokenMinter) dropAgent(agentID, system string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for k, c := range m.cache {
		if c.agentID == agentID && (system == "" || c.system == system) {
			delete(m.cache, k)
			n++
		}
	}
	return n
}

// mintDWD exchanges a service-account JWT (sub = subject) for an access token.
func mintDWD(ctx context.Context, client *http.Client, tokenURL string, saJSON []byte, subject string, scopes []string) (*oauth2.Token, error) {
	cfg, err := googleoauth.JWTConfigFromJSON(saJSON, scopes...)
	if err != nil {
		return nil, fmt.Errorf("%w: service account key unusable", errMint)
	}
	cfg.Subject = subject
	cfg.TokenURL = tokenURL
	if client != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, client)
	}
	tok, err := cfg.TokenSource(ctx).Token()
	if err != nil {
		return nil, fmt.Errorf("%w: %s", errMint, sanitizeTokenError(err))
	}
	if tok.AccessToken == "" {
		return nil, fmt.Errorf("%w: empty access token", errMint)
	}
	return tok, nil
}

// sanitizeTokenError keeps the OAuth error code/description and drops raw
// response bodies.
func sanitizeTokenError(err error) string {
	var re *oauth2.RetrieveError
	if errors.As(err, &re) {
		msg := "token endpoint refused"
		if re.Response != nil {
			msg += fmt.Sprintf(" (HTTP %d)", re.Response.StatusCode)
		}
		code, desc := re.ErrorCode, re.ErrorDescription
		if code == "" {
			// The JWT flow does not parse the body; Google answers
			// {"error": "...", "error_description": "..."} (no secrets).
			var b struct {
				Error       string `json:"error"`
				Description string `json:"error_description"`
			}
			if json.Unmarshal(re.Body, &b) == nil {
				code, desc = b.Error, b.Description
			}
		}
		if code != "" {
			msg += ": " + truncate(code, 64)
		}
		if desc != "" {
			msg += ": " + truncate(desc, 200)
		}
		return msg
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "token endpoint timed out"
	}
	return "token endpoint unreachable"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
