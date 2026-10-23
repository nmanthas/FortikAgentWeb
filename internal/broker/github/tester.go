package github

import (
	"context"
	"fmt"
	"time"

	"fortik/internal/integrations"
)

// Tester is the live connection test for the "github" integration
// (POST /v1/integrations/github/test): app JWT → GET /app/installations/{id}
// → mint a minimal (metadata:read) token → revoke it.
type Tester struct{ Client *Client }

var _ integrations.Tester = Tester{}

// NewTester returns a tester sharing c (nil = a fresh client).
func NewTester(c *Client) Tester {
	if c == nil {
		c = NewClient(nil)
	}
	return Tester{Client: c}
}

func (Tester) System() string { return System }

// Test returns a sanitised error (never key material or tokens).
func (t Tester) Test(ctx context.Context, r integrations.Resolved) error {
	c := t.Client
	if c == nil {
		c = NewClient(nil)
	}
	s, err := c.Settings(r)
	if err != nil {
		return err
	}
	// Bypass the installation cache: a test must hit GitHub.
	c.instMu.Lock()
	delete(c.inst, s.Fingerprint)
	c.instMu.Unlock()
	inst, err := c.Installation(ctx, s)
	if err != nil {
		return fmt.Errorf("app authentication or installation lookup failed: %w", err)
	}
	tok, err := c.MintToken(ctx, s, nil, map[string]string{"metadata": "read"})
	if err != nil {
		return fmt.Errorf("installation %d (account %s): minting a minimal token failed: %w", inst.ID, inst.Account, err)
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := c.RevokeToken(rctx, s.BaseURL, tok.Secret); err != nil {
		return fmt.Errorf("minted a test token but could not revoke it (it expires within 1h): %w", err)
	}
	return nil
}
