package pgproxy

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"fortik/internal/config"
	"fortik/internal/tlsx"
)

// Phase 6 mTLS: with tls_required and a client CA, the proxy refuses a
// plaintext client and a TLS client without a certificate, and serves one
// that presents a certificate issued by the CA.
func TestProxyRequiresMutualTLS(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	if _, err := tlsx.DevCerts(dir, []string{"localhost", "127.0.0.1"}, []string{"agent"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	f := func(n string) string { return filepath.Join(dir, n) }
	h := newHarnessWith(t, func(c *config.PGProxyConfig) {
		c.TLSCertFile, c.TLSKeyFile = f("server.crt"), f("server.key")
		c.TLSClientCAFile, c.TLSClientAuth, c.TLSRequired = f("ca.crt"), "require", true
	})
	try := func(params string) error {
		u := fmt.Sprintf("postgres://%s:%s@%s/%s?%s", testAgent, testToken, h.addr, upName, params)
		cfg, err := pgx.ParseConfig(u)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, err := pgx.ConnectConfig(ctx, cfg)
		if err != nil {
			return err
		}
		defer c.Close(ctx)
		var one int
		return c.QueryRow(ctx, "SELECT 1").Scan(&one)
	}
	if err := try("sslmode=disable"); err == nil || !strings.Contains(err.Error(), "TLS is required") {
		t.Fatalf("plaintext client: %v", err)
	}
	if err := try("sslmode=verify-full&sslrootcert=" + f("ca.crt")); err == nil {
		t.Fatal("TLS client without a certificate was served")
	}
	if err := try("sslmode=verify-full&sslrootcert=" + f("ca.crt") + "&sslcert=" + f("client-agent.crt") + "&sslkey=" + f("client-agent.key")); err != nil {
		t.Fatalf("client with an issued certificate: %v", err)
	}
}
