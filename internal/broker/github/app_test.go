package github_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"fortik/internal/broker"
	ghbroker "fortik/internal/broker/github"
	"fortik/internal/broker/github/fakegithub"
	"fortik/internal/integrations"
)

func resolved(f *fakegithub.Server) integrations.Resolved {
	return integrations.Resolved{
		Integration: integrations.Integration{Key: "github", System: "github"},
		ConfigMap:   map[string]any{"api_base_url": f.URL, "app_id": f.AppID, "installation_id": f.InstallationID},
		Secrets:     map[string]string{"private_key_pem": f.PrivateKeyPEM},
	}
}

func TestSettingsValidation(t *testing.T) {
	f := fakegithub.New(t)
	c := ghbroker.NewClient(nil)

	r := resolved(f)
	r.ConfigMap["app_id"] = float64(4242) // JSON numbers decode as float64
	if s, err := c.Settings(r); err != nil || s.AppID != "4242" || s.Fingerprint == "" {
		t.Fatalf("numeric app_id: %+v %v", s, err)
	}

	missingKey := resolved(f)
	delete(missingKey.Secrets, "private_key_pem")
	_, err := c.Settings(missingKey)
	if !errors.Is(err, integrations.ErrNotConfigured) || !errors.Is(err, broker.ErrNotConfigured) {
		t.Fatalf("missing key: want not-configured (both sentinels), got %v", err)
	}
	missingID := resolved(f)
	delete(missingID.ConfigMap, "installation_id")
	if _, err := c.Settings(missingID); !errors.Is(err, integrations.ErrNotConfigured) {
		t.Fatalf("missing installation id: %v", err)
	}

	for _, base := range []string{"http://api.example.com", "ftp://x", "https://user:pw@api.github.com", "https://h/x?q=1"} {
		bad := resolved(f)
		bad.ConfigMap["api_base_url"] = base
		if _, err := c.Settings(bad); !errors.Is(err, integrations.ErrInvalid) {
			t.Fatalf("base %q: want ErrInvalid, got %v", base, err)
		}
	}

	badKey := resolved(f)
	badKey.Secrets["private_key_pem"] = "-----BEGIN RSA PRIVATE KEY-----\nTOPSECRETMATERIAL\n-----END RSA PRIVATE KEY-----\n"
	_, err = c.Settings(badKey)
	if !errors.Is(err, integrations.ErrInvalid) || strings.Contains(err.Error(), "TOPSECRET") {
		t.Fatalf("bad key: want sanitised ErrInvalid, got %v", err)
	}

	defaults := resolved(f)
	delete(defaults.ConfigMap, "api_base_url")
	if s, err := c.Settings(defaults); err != nil || s.BaseURL != ghbroker.DefaultBaseURL {
		t.Fatalf("default base: %q %v", s.BaseURL, err)
	}
}

func TestAppJWTClaims(t *testing.T) {
	f := fakegithub.New(t)
	c := ghbroker.NewClient(nil)
	now := time.Now()
	c.Now = func() time.Time { return now }
	s, err := c.Settings(resolved(f))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := c.AppJWT(s)
	if err != nil {
		t.Fatal(err)
	}
	claims := &jwt.RegisteredClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(raw, claims); err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != "4242" {
		t.Fatalf("iss = %q", claims.Issuer)
	}
	if got := now.Sub(claims.IssuedAt.Time); got < 59*time.Second || got > 61*time.Second {
		t.Fatalf("iat should be now-60s, is now-%s", got)
	}
	if life := claims.ExpiresAt.Sub(claims.IssuedAt.Time); life > 10*time.Minute+time.Minute {
		t.Fatalf("JWT lifetime %s exceeds GitHub's limit", life)
	}
	if claims.ExpiresAt.Sub(now) > 10*time.Minute {
		t.Fatal("exp more than 10 minutes ahead")
	}
	// The fake verifies the signature with the app's public key.
	if inst, err := c.Installation(context.Background(), s); err != nil || inst.Account != "acme" {
		t.Fatalf("installation via signed JWT: %+v %v", inst, err)
	}
}

func TestMintTokenNarrowAndVerified(t *testing.T) {
	f := fakegithub.New(t)
	f.AddRepo("acme", "api")
	f.AddRepo("acme", "web")
	c := ghbroker.NewClient(nil)
	s, _ := c.Settings(resolved(f))
	ctx := context.Background()

	tok, err := c.MintToken(ctx, s, []string{"api"}, map[string]string{"contents": "read"})
	if err != nil {
		t.Fatal(err)
	}
	if len(tok.Repos) != 1 || tok.Repos[0] != "api" || tok.Permissions["contents"] != "read" || len(tok.Permissions) != 1 {
		t.Fatalf("token scope: %+v", tok)
	}
	if time.Until(tok.ExpiresAt) < 50*time.Minute {
		t.Fatalf("unexpected expiry %s", tok.ExpiresAt)
	}
	// Redaction: no formatting path exposes the secret.
	for _, s := range []string{fmt.Sprint(tok), fmt.Sprintf("%+v", tok), fmt.Sprintf("%v", &tok), mustJSON(t, tok)} {
		if strings.Contains(s, tok.Secret) {
			t.Fatalf("token secret leaked through formatting: %s", s)
		}
	}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("minted", "token", tok)
	if strings.Contains(buf.String(), tok.Secret) {
		t.Fatal("token secret leaked into slog output")
	}

	if _, err := c.MintToken(ctx, s, []string{"api"}, nil); err == nil {
		t.Fatal("a token without explicit permissions must be refused (GitHub would grant everything)")
	}
	if _, err := c.MintToken(ctx, s, []string{"api"}, map[string]string{"contents": "superuser"}); err == nil {
		t.Fatal("invalid level accepted")
	}

	// A misbehaving upstream granting more than requested: refused and revoked.
	f.SetGrantExtra(true)
	_, err = c.MintToken(ctx, s, []string{"api"}, map[string]string{"contents": "read"})
	if err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("over-grant must be refused, got %v", err)
	}
	f.SetGrantExtra(false)
	revoked := 0
	for _, tk := range f.Tokens() {
		if tk.Permissions["administration"] == "write" && tk.Revoked {
			revoked++
		}
	}
	if revoked != 1 {
		t.Fatalf("over-granted token not revoked (revoked=%d)", revoked)
	}

	if err := c.RevokeToken(ctx, s.BaseURL, tok.Secret); err != nil {
		t.Fatal(err)
	}
	// Revoking an already-invalid token counts as revoked.
	if err := c.RevokeToken(ctx, s.BaseURL, tok.Secret); err != nil {
		t.Fatalf("second revoke: %v", err)
	}
}

func TestCheckOwner(t *testing.T) {
	f := fakegithub.New(t)
	c := ghbroker.NewClient(nil)
	s, _ := c.Settings(resolved(f))
	if err := c.CheckOwner(context.Background(), s, "ACME"); err != nil {
		t.Fatalf("owner match is case-insensitive: %v", err)
	}
	if err := c.CheckOwner(context.Background(), s, "evil"); !errors.Is(err, ghbroker.ErrWrongOwner) {
		t.Fatalf("want ErrWrongOwner, got %v", err)
	}
}

func TestTester(t *testing.T) {
	f := fakegithub.New(t)
	tester := ghbroker.NewTester(nil)
	if tester.System() != "github" {
		t.Fatal(tester.System())
	}
	if err := tester.Test(context.Background(), resolved(f)); err != nil {
		t.Fatalf("tester: %v", err)
	}
	if f.CallsMatching("GET", "/app/installations/777") != 1 || f.CallsMatching("POST", "/app/installations/777/access_tokens") != 1 ||
		f.CallsMatching("DELETE", "/installation/token") != 1 {
		t.Fatalf("tester did not follow JWT -> installation -> mint -> revoke: %+v", f.Calls())
	}
	if f.LiveTokens() != 0 {
		t.Fatal("tester left a live token")
	}
	toks := f.Tokens()
	if len(toks) != 1 || len(toks[0].Permissions) != 1 || toks[0].Permissions["metadata"] != "read" {
		t.Fatalf("tester token must be minimal: %+v", toks)
	}

	// A wrong installation fails with a sanitised message.
	bad := resolved(f)
	bad.ConfigMap["installation_id"] = "999"
	err := tester.Test(context.Background(), bad)
	if err == nil || strings.Contains(err.Error(), "PRIVATE KEY") {
		t.Fatalf("wrong installation: %v", err)
	}
	other := fakegithub.New(t) // a different app key: JWT rejected
	wrongKey := resolved(f)
	wrongKey.Secrets["private_key_pem"] = other.PrivateKeyPEM
	if err := tester.Test(context.Background(), wrongKey); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("wrong key: want 401, got %v", err)
	}
	notConfigured := resolved(f)
	delete(notConfigured.Secrets, "private_key_pem")
	if err := tester.Test(context.Background(), notConfigured); !errors.Is(err, integrations.ErrNotConfigured) {
		t.Fatalf("not configured: %v", err)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
