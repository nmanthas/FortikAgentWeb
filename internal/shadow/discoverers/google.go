package discoverers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"golang.org/x/oauth2"
	googleoauth "golang.org/x/oauth2/google"

	"fortik/internal/integrations"
	"fortik/internal/shadow"
)

// Admin SDK scopes the service account's domain-wide delegation must allow
// for discovery (read) and revocation (security).
const (
	ScopeAdminUsersRead = "https://www.googleapis.com/auth/admin.directory.user.readonly"
	ScopeAdminSecurity  = "https://www.googleapis.com/auth/admin.directory.user.security"
	// DefaultAdminBaseURL is the Admin SDK Directory API host.
	DefaultAdminBaseURL = "https://admin.googleapis.com"
)

// Google discovers third-party OAuth grants in Google Workspace (Admin SDK
// Directory users.list + tokens.list per user), impersonating a Workspace
// admin through the configured service account's domain-wide delegation.
type Google struct {
	src      integrations.Source
	hc       *http.Client
	tokenURL string
	base     string
	maxUsers int
	log      *slog.Logger
}

// NewGoogle returns the Google Workspace discoverer and revoker. tokenURL
// and adminBaseURL default to Google's (override only for local fakes).
func NewGoogle(src integrations.Source, hc *http.Client, tokenURL, adminBaseURL string, log *slog.Logger) *Google {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	c := *hc
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if tokenURL == "" {
		tokenURL = googleoauth.JWTTokenURL
	}
	if adminBaseURL == "" {
		adminBaseURL = DefaultAdminBaseURL
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Google{src: src, hc: &c, tokenURL: tokenURL, base: strings.TrimRight(adminBaseURL, "/"), maxUsers: 5000,
		log: log.With("component", "shadow-google")}
}

func (g *Google) System() string { return shadow.SystemGoogle }

// safeURL refuses anything but https, except http to a loopback host.
func safeURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme != "http" {
		return false
	}
	h := u.Hostname()
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

type googleSettings struct {
	saJSON  []byte
	subject string
}

func (g *Google) settings(ctx context.Context) (googleSettings, *shadow.ScanResult) {
	res := &shadow.ScanResult{System: shadow.SystemGoogle, Integration: integrations.SystemGoogle}
	if g.src == nil {
		res.Status, res.Detail = shadow.ScanNotConfigured, "no integrations source: not scanned"
		return googleSettings{}, res
	}
	r, err := g.src.Get(ctx, integrations.SystemGoogle)
	switch {
	case errors.Is(err, integrations.ErrSecretMissing):
		res.Status, res.Detail = shadow.ScanError, "the google_workspace integration is configured but its service account key is missing: not scanned"
		return googleSettings{}, res
	case errors.Is(err, integrations.ErrNotConfigured):
		res.Status, res.Detail = shadow.ScanNotConfigured, "the google_workspace integration is not configured: not scanned"
		return googleSettings{}, res
	case err != nil:
		res.Status, res.Detail = shadow.ScanError, "could not read the google_workspace integration: not scanned"
		return googleSettings{}, res
	}
	if !safeURL(g.tokenURL) || !safeURL(g.base) {
		res.Status, res.Detail = shadow.ScanError, "the Google token or Admin SDK URL is not https: not scanned"
		return googleSettings{}, res
	}
	s := googleSettings{saJSON: []byte(r.Secret("service_account_json"))}
	// The Admin SDK must impersonate a Workspace admin: admin_user when the
	// integration has one, otherwise the test user (which must then be an
	// admin with the user-security privilege).
	s.subject = strings.TrimSpace(r.Text("admin_user"))
	if s.subject == "" {
		s.subject = strings.TrimSpace(r.Text("test_user"))
	}
	if len(s.saJSON) == 0 || s.subject == "" {
		res.Status, res.Detail = shadow.ScanNotConfigured, "the google_workspace integration has no service account key or admin user: not scanned"
		return googleSettings{}, res
	}
	return s, nil
}

func (g *Google) token(ctx context.Context, s googleSettings, scopes ...string) (string, error) {
	cfg, err := googleoauth.JWTConfigFromJSON(s.saJSON, scopes...)
	if err != nil {
		return "", errors.New("the service account key is unusable")
	}
	cfg.Subject = s.subject
	cfg.TokenURL = g.tokenURL
	tok, err := cfg.TokenSource(context.WithValue(ctx, oauth2.HTTPClient, g.hc)).Token()
	if err != nil {
		var re *oauth2.RetrieveError
		if errors.As(err, &re) && re.Response != nil {
			var b struct {
				Error string `json:"error"`
			}
			_ = json.Unmarshal(re.Body, &b)
			return "", fmt.Errorf("token endpoint refused (HTTP %d %s): check the service account's domain-wide delegation for the Admin SDK scopes and that %s is an admin",
				re.Response.StatusCode, shadow.Clean(b.Error, 64), s.subject)
		}
		return "", errors.New("token endpoint unreachable")
	}
	if tok.AccessToken == "" {
		return "", errors.New("empty access token")
	}
	return tok.AccessToken, nil
}

func (g *Google) call(ctx context.Context, tok, method, path string, out any, ok ...int) (int, error) {
	req, err := http.NewRequestWithContext(ctx, method, g.base+path, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	resp, err := g.hc.Do(req)
	if err != nil {
		return 0, errors.New("request failed")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return resp.StatusCode, errors.New("read response failed")
	}
	for _, c := range ok {
		if resp.StatusCode == c {
			if out != nil && len(raw) > 0 {
				if err := json.Unmarshal(raw, out); err != nil {
					return resp.StatusCode, errors.New("malformed response")
				}
			}
			return resp.StatusCode, nil
		}
	}
	var e struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(raw, &e)
	return resp.StatusCode, fmt.Errorf("HTTP %d %s", resp.StatusCode, shadow.Clean(e.Error.Message, 200))
}

type gToken struct {
	ClientID    string   `json:"clientId"`
	DisplayText string   `json:"displayText"`
	Anonymous   bool     `json:"anonymous"`
	NativeApp   bool     `json:"nativeApp"`
	Scopes      []string `json:"scopes"`
	UserKey     string   `json:"userKey"`
}

type gClient struct {
	tok   gToken
	users []string
	count int
}

// listUsers lists the domain's users (up to maxUsers; truncated says more exist).
func (g *Google) listUsers(ctx context.Context, tok string) ([]string, bool, error) {
	var users []string
	pageToken := ""
	for {
		q := url.Values{"customer": {"my_customer"}, "maxResults": {"500"}, "projection": {"basic"}}
		if pageToken != "" {
			q.Set("pageToken", pageToken)
		}
		var page struct {
			Users []struct {
				PrimaryEmail string `json:"primaryEmail"`
			} `json:"users"`
			NextPageToken string `json:"nextPageToken"`
		}
		if _, err := g.call(ctx, tok, http.MethodGet, "/admin/directory/v1/users?"+q.Encode(), &page, http.StatusOK); err != nil {
			return nil, false, fmt.Errorf("Admin SDK users.list failed (%s)", err.Error())
		}
		for _, u := range page.Users {
			if u.PrimaryEmail != "" {
				users = append(users, u.PrimaryEmail)
			}
		}
		if len(users) >= g.maxUsers {
			return users[:g.maxUsers], true, nil
		}
		if page.NextPageToken == "" {
			return users, false, nil
		}
		pageToken = page.NextPageToken
	}
}

// Discover implements shadow.Discoverer.
func (g *Google) Discover(ctx context.Context) []shadow.ScanResult {
	s, bad := g.settings(ctx)
	if bad != nil {
		return []shadow.ScanResult{*bad}
	}
	res := shadow.ScanResult{System: shadow.SystemGoogle, Integration: integrations.SystemGoogle}
	tok, err := g.token(ctx, s, ScopeAdminUsersRead, ScopeAdminSecurity)
	if err != nil {
		res.Status, res.Detail = shadow.ScanError, err.Error()+": not scanned"
		return []shadow.ScanResult{res}
	}
	users, truncated, err := g.listUsers(ctx, tok)
	if err != nil {
		res.Status, res.Detail = shadow.ScanError, err.Error()+": not scanned"
		return []shadow.ScanResult{res}
	}
	clients := map[string]*gClient{}
	var failures []string
	failed := 0
	for _, u := range users {
		var out struct {
			Items []gToken `json:"items"`
		}
		if _, err := g.call(ctx, tok, http.MethodGet, "/admin/directory/v1/users/"+url.PathEscape(u)+"/tokens", &out, http.StatusOK); err != nil {
			failed++
			if len(failures) < 3 {
				failures = append(failures, "tokens.list for "+u+" failed ("+err.Error()+")")
			}
			continue
		}
		for _, t := range out.Items {
			if t.ClientID == "" {
				continue
			}
			c := clients[t.ClientID]
			if c == nil {
				c = &gClient{tok: t}
				clients[t.ClientID] = c
			}
			c.count++
			if len(c.users) < 50 {
				c.users = append(c.users, u)
			}
		}
	}
	ids := make([]string, 0, len(clients))
	for id := range clients {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		res.Credentials = append(res.Credentials, classifyGrant(clients[id]))
	}
	notes := []string{fmt.Sprintf("%d user(s), %d distinct OAuth client(s) with grants", len(users), len(clients))}
	res.Status = shadow.ScanScanned
	if truncated {
		res.Status = shadow.ScanPartial
		notes = append(notes, fmt.Sprintf("only the first %d users were examined", g.maxUsers))
	}
	if failed > 0 {
		res.Status = shadow.ScanPartial
		notes = append(notes, fmt.Sprintf("%d user(s) NOT scanned: %s", failed, strings.Join(failures, "; ")))
	}
	res.Detail = strings.Join(notes, "; ")
	return []shadow.ScanResult{res}
}

func classifyGrant(c *gClient) shadow.Credential {
	t := c.tok
	hint := shadow.SoftwareHint(t.DisplayText)
	var why []string
	if t.Anonymous {
		why = append(why, "the OAuth client is not registered (anonymous): typical of scripts")
	}
	if hint != "" {
		why = append(why, "the client's name suggests automation ("+hint+")")
	}
	software := len(why) > 0
	reason := strings.Join(why, "; ")
	if !software {
		kind := "web"
		if t.NativeApp {
			kind = "native"
		}
		reason = "a registered " + kind + " app a person signed in to (no software indicator)"
	}
	scopes := append([]string(nil), t.Scopes...)
	sort.Strings(scopes)
	holder := ""
	if len(c.users) > 0 {
		holder = c.users[0]
	}
	if c.count > 1 {
		holder = fmt.Sprintf("%d users", c.count)
	}
	ev := map[string]any{"client_id": t.ClientID, "display_text": shadow.Clean(t.DisplayText, 120), "anonymous": t.Anonymous,
		"native_app": t.NativeApp, "scopes": limit(scopes, 20), "users": c.users, "user_count": c.count, "classified_by": reason}
	name := t.DisplayText
	if name == "" {
		name = t.ClientID
	}
	return shadow.Credential{Kind: shadow.KindOAuthGrant, Ref: shadow.Clean(t.ClientID, 200), Holder: holder, Software: software,
		Integration: integrations.SystemGoogle, Label: shadow.Clean("Google OAuth client "+name, 200), Evidence: ev}
}

// Revoke implements shadow.Revoker: deletes the client's token for every
// user recorded on the finding (Admin SDK tokens.delete). It is revoked only
// when every holder was recorded and every delete succeeded.
func (g *Google) Revoke(ctx context.Context, f shadow.Finding) shadow.RevokeResult {
	if f.Kind != shadow.KindOAuthGrant {
		return shadow.RevokeResult{Outcome: shadow.OutcomeManualRequired, Detail: "flagged: revoke it in the Google Admin console"}
	}
	var ev struct {
		Users     []string `json:"users"`
		UserCount int      `json:"user_count"`
		ClientID  string   `json:"client_id"`
	}
	_ = json.Unmarshal(f.Evidence, &ev)
	if ev.ClientID == "" || ev.ClientID != f.CredentialRef || len(ev.Users) == 0 {
		return shadow.RevokeResult{Outcome: shadow.OutcomeNotRevoked, Detail: "the finding does not list the grant's users: NOT revoked"}
	}
	s, bad := g.settings(ctx)
	if bad != nil {
		return shadow.RevokeResult{Outcome: shadow.OutcomeNotRevoked, Detail: bad.Detail + " (revoke)"}
	}
	tok, err := g.token(ctx, s, ScopeAdminUsersRead, ScopeAdminSecurity)
	if err != nil {
		return shadow.RevokeResult{Outcome: shadow.OutcomeNotRevoked, Detail: err.Error() + ": NOT revoked"}
	}
	// The finding's user list is a snapshot of the last scan (which may have
	// been partial, and users may have granted the client since): the holders
	// are enumerated again now, and success is claimed only when every
	// user of the domain was checked and every grant of this client deleted.
	all, truncated, lerr := g.listUsers(ctx, tok)
	holders := append([]string{}, ev.Users...)
	unchecked := []string{}
	if lerr == nil {
		seen := map[string]bool{}
		for _, u := range holders {
			seen[strings.ToLower(u)] = true
		}
		for _, u := range all {
			if seen[strings.ToLower(u)] {
				continue
			}
			var out struct {
				Items []gToken `json:"items"`
			}
			if _, err := g.call(ctx, tok, http.MethodGet, "/admin/directory/v1/users/"+url.PathEscape(u)+"/tokens", &out, http.StatusOK); err != nil {
				unchecked = append(unchecked, u)
				continue
			}
			for _, t := range out.Items {
				if t.ClientID == ev.ClientID {
					holders = append(holders, u)
					break
				}
			}
		}
	}
	done, failed := 0, []string{}
	for _, u := range holders {
		_, err := g.call(ctx, tok, http.MethodDelete, "/admin/directory/v1/users/"+url.PathEscape(u)+"/tokens/"+url.PathEscape(ev.ClientID), nil,
			http.StatusNoContent, http.StatusOK, http.StatusNotFound)
		if err != nil {
			failed = append(failed, u)
			continue
		}
		done++
	}
	console := " revoke the remaining grants in the Google Admin console (Security > API controls > App access control)"
	switch {
	case len(failed) > 0:
		return shadow.RevokeResult{Outcome: shadow.OutcomeNotRevoked, Detail: fmt.Sprintf("tokens deleted for %d of %d user(s); failed for %s: NOT fully revoked;%s",
			done, len(holders), strings.Join(limit(failed, 5), ", "), console)}
	case lerr != nil:
		return shadow.RevokeResult{Outcome: shadow.OutcomeNotRevoked, Detail: fmt.Sprintf("tokens deleted for the %d recorded user(s), but the other users could not be checked (%s): NOT verified as revoked;%s",
			done, shadow.Clean(lerr.Error(), 200), console)}
	case truncated:
		return shadow.RevokeResult{Outcome: shadow.OutcomeNotRevoked, Detail: fmt.Sprintf("tokens deleted for %d user(s), but only the first %d users of the domain could be checked: NOT verified as revoked;%s",
			done, g.maxUsers, console)}
	case len(unchecked) > 0:
		return shadow.RevokeResult{Outcome: shadow.OutcomeNotRevoked, Detail: fmt.Sprintf("tokens deleted for %d user(s), but %d user(s) could not be checked (%s): NOT verified as revoked;%s",
			done, len(unchecked), strings.Join(limit(unchecked, 5), ", "), console)}
	}
	return shadow.RevokeResult{Outcome: shadow.OutcomeRevoked, Detail: fmt.Sprintf("OAuth client %s: tokens deleted for all %d holder(s); all %d user(s) of the domain checked", ev.ClientID, done, len(all))}
}
