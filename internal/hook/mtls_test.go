package hook

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fortik/internal/config"
	"fortik/internal/tlsx"
)

// Phase 6 mTLS: against a gateway that requires client certificates the
// hook allows only with this machine's certificate, and blocks (fails
// closed) without it or with unusable TLS settings.
func TestClientMutualTLS(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	if _, err := tlsx.DevCerts(dir, []string{"localhost", "127.0.0.1"}, []string{"hook"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	f := func(n string) string { return filepath.Join(dir, n) }
	tc, err := tlsx.Server(config.TLSConfig{CertFile: f("server.crt"), KeyFile: f("server.key"), ClientCAFile: f("ca.crt")})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"decision":"allow","class":"green","rule_id":"POL-000","reason":"ok","action_id":"a1"}`)
	}))
	srv.TLS = tc
	srv.StartTLS()
	defer srv.Close()
	url := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)

	env := baseEnv(url)
	env["FORTIK_CA_FILE"] = f("ca.crt")
	if code, _, stderr := run(t, strings.NewReader(sampleEvent), env); code != ExitBlock || !strings.Contains(stderr, "fail closed") {
		t.Fatalf("without a client certificate: %d %s", code, stderr)
	}
	env["FORTIK_CLIENT_CERT"], env["FORTIK_CLIENT_KEY"] = f("client-hook.crt"), f("client-hook.key")
	if code, _, stderr := run(t, strings.NewReader(sampleEvent), env); code != ExitAllow {
		t.Fatalf("with the client certificate: %d %s", code, stderr)
	}
	env["FORTIK_CLIENT_KEY"] = filepath.Join(dir, "missing.key")
	if code, _, stderr := run(t, strings.NewReader(sampleEvent), env); code != ExitBlock || !strings.Contains(stderr, "TLS settings unusable") {
		t.Fatalf("broken TLS settings: %d %s", code, stderr)
	}
}
