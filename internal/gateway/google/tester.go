package google

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"fortik/internal/config"
	"fortik/internal/gateway"
	"fortik/internal/integrations"
)

// Tester is the live connection test for google_workspace: it mints a
// domain-wide-delegation token for test_user and calls gmail users.getProfile.
type Tester struct {
	client    *http.Client
	tokenURL  string
	gmailBase string
}

// NewTester uses the same token URL and Gmail base overrides as the gateway.
func NewTester(cfg config.GatewayConfig, client *http.Client) *Tester {
	if client == nil {
		client = http.DefaultClient
	}
	tu := cfg.GoogleTokenURL
	if tu == "" {
		tu = DefaultTokenURL
	}
	return &Tester{client: client, tokenURL: tu, gmailBase: base(cfg.GmailBaseURL, DefaultGmailBaseURL)}
}

var _ integrations.Tester = (*Tester)(nil)

func (t *Tester) System() string { return IntegrationKey }

// Test returns a sanitised error (no secrets, no raw response bodies).
func (t *Tester) Test(ctx context.Context, r integrations.Resolved) error {
	s, err := parseSettings(r)
	if err != nil {
		return err
	}
	if s.testUser == "" || domainOf(s.testUser) == "" {
		return fmt.Errorf("%w: test_user must be a Workspace email address", integrations.ErrInvalid)
	}
	tok, err := mintDWD(ctx, t.client, t.tokenURL, s.saJSON, s.testUser, []string{ScopeGmailReadonly})
	if err != nil {
		return fmt.Errorf("domain-wide delegation for %s failed (check the client id is authorised for %s): %w",
			s.testUser, ScopeGmailReadonly, err)
	}
	resp, err := gateway.Do(ctx, gateway.ProxyRequest{Client: t.client, Method: http.MethodGet, URL: t.gmailBase + "/gmail/v1/users/me/profile",
		ForwardHeaders: []string{}, SetHeader: http.Header{"Accept": {"application/json"}}, Authorization: "Bearer " + tok.AccessToken})
	if err != nil {
		return errors.New("gmail users.getProfile: request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("gmail users.getProfile returned HTTP %d (is the Gmail API enabled for the project?)", resp.StatusCode)
	}
	var prof struct {
		EmailAddress string `json:"emailAddress"`
	}
	if err := decodeLimited(resp, &prof); err != nil {
		return errors.New("gmail users.getProfile: response not understood")
	}
	if !strings.EqualFold(prof.EmailAddress, s.testUser) {
		return errors.New("gmail users.getProfile answered for a different mailbox than test_user")
	}
	return nil
}

func decodeLimited(resp *http.Response, v any) error {
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v)
}
