package tlsx_test

import (
	"crypto/tls"
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

func pki(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "tls")
	if _, err := tlsx.DevCerts(dir, []string{"localhost", "127.0.0.1"}, []string{"hook"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	return dir
}

// Mutual TLS: a listener with client_auth require refuses a client without a
// certificate (or with one from another CA) and accepts the issued one.
func TestMutualTLSRequiresAClientCertificate(t *testing.T) {
	dir, other := pki(t), pki(t)
	f := func(n string) string { return filepath.Join(dir, n) }
	srvCfg, err := tlsx.Server(config.TLSConfig{CertFile: f("server.crt"), KeyFile: f("server.key"), ClientCAFile: f("ca.crt"), ClientAuth: "require"})
	if err != nil || srvCfg.ClientAuth != tls.RequireAndVerifyClientCert || srvCfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("server config: %+v %v", srvCfg, err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.TLS.PeerCertificates[0].Subject.CommonName)
	}))
	srv.TLS = srvCfg
	srv.StartTLS()
	defer srv.Close()
	get := func(cfg *tls.Config) (string, error) {
		cl := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 5 * time.Second}
		res, err := cl.Get(strings.Replace(srv.URL, "127.0.0.1", "localhost", 1))
		if err != nil {
			return "", err
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return string(b), nil
	}
	noCert, _ := tlsx.Client(f("ca.crt"), "", "")
	if _, err := get(noCert); err == nil {
		t.Fatal("a client without a certificate was accepted")
	}
	wrongCA, _ := tlsx.Client(f("ca.crt"), filepath.Join(other, "client-hook.crt"), filepath.Join(other, "client-hook.key"))
	if _, err := get(wrongCA); err == nil {
		t.Fatal("a client certificate from another CA was accepted")
	}
	good, err := tlsx.Client(f("ca.crt"), f("client-hook.crt"), f("client-hook.key"))
	if err != nil {
		t.Fatal(err)
	}
	if cn, err := get(good); err != nil || cn != "hook" {
		t.Fatalf("issued client certificate: %q %v", cn, err)
	}
	untrusting, _ := tlsx.Client(filepath.Join(other, "ca.crt"), f("client-hook.crt"), f("client-hook.key"))
	if _, err := get(untrusting); err == nil {
		t.Fatal("client trusted a server certificate from another CA")
	}
}

func TestServerConfigValidation(t *testing.T) {
	dir := pki(t)
	f := func(n string) string { return filepath.Join(dir, n) }
	for name, c := range map[string]config.TLSConfig{
		"key without cert":      {KeyFile: f("server.key")},
		"client ca without tls": {ClientCAFile: f("ca.crt")},
		"require without ca":    {CertFile: f("server.crt"), KeyFile: f("server.key"), ClientAuth: "require"},
		"bad mode":              {CertFile: f("server.crt"), KeyFile: f("server.key"), ClientCAFile: f("ca.crt"), ClientAuth: "maybe"},
		"ca with none":          {CertFile: f("server.crt"), KeyFile: f("server.key"), ClientCAFile: f("ca.crt"), ClientAuth: "none"},
	} {
		if _, err := tlsx.Server(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if c, err := tlsx.Server(config.TLSConfig{}); c != nil || err != nil {
		t.Fatalf("no TLS: %v %v", c, err)
	}
	// client_ca_file alone means require.
	c, err := tlsx.Server(config.TLSConfig{CertFile: f("server.crt"), KeyFile: f("server.key"), ClientCAFile: f("ca.crt")})
	if err != nil || c.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("default client auth: %v %v", c, err)
	}
	if _, err := tlsx.DevCerts(dir, []string{"x"}, nil, time.Hour); err == nil {
		t.Fatal("DevCerts overwrote an existing CA")
	}
}
