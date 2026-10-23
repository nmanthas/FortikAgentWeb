package secrets_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"fortik/internal/config"
	"fortik/internal/secrets"
)

const baoBinary = "/opt/homebrew/bin/bao"

// startBao runs a real OpenBao dev server (in-memory, KV v2 mounted at
// "secret/") on a free loopback port and stops it when the test ends.
func startBao(t *testing.T) (addr, token string) {
	t.Helper()
	bin := baoBinary
	if _, err := os.Stat(bin); err != nil {
		p, lerr := exec.LookPath("bao")
		if lerr != nil {
			t.Skipf("vault integration test skipped: OpenBao binary not found at %s or on PATH", baoBinary)
		}
		bin = p
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	tb := make([]byte, 16)
	_, _ = rand.Read(tb)
	token = "root-" + hex.EncodeToString(tb)
	addr = fmt.Sprintf("http://127.0.0.1:%d", port)

	cmd := exec.Command(bin, "server", "-dev", "-dev-root-token-id="+token, fmt.Sprintf("-dev-listen-address=127.0.0.1:%d", port))
	// Isolate HOME so the dev server's token helper never touches the
	// developer's ~/.vault-token.
	home := t.TempDir()
	cmd.Env = append(os.Environ(), "HOME="+home, "BAO_ADDR="+addr, "VAULT_ADDR="+addr)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start bao: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	deadline := time.Now().Add(20 * time.Second)
	for {
		resp, err := http.Get(addr + "/v1/sys/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("bao did not become healthy; output:\n%s", out.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	return addr, token
}

func TestVaultAgainstOpenBao(t *testing.T) {
	addr, token := startBao(t)
	ctx := context.Background()
	t.Setenv(secrets.EnvVaultToken, token)
	p, err := secrets.Open(config.SecretsConfig{Provider: "vault", VaultAddr: addr, VaultMount: "secret", VaultPrefix: "fortik/"})
	if err != nil {
		t.Fatal(err)
	}
	v := p.(*secrets.Vault)
	if s := fmt.Sprintf("%v %+v %#v", v, v, v); strings.Contains(s, token) {
		t.Fatal("formatting the store leaks the token")
	}

	name := "integration/postgres/acme_prod/admin_password"
	if _, err := v.Get(ctx, name); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("missing: want ErrNotFound, got %v", err)
	}
	val := []byte("p@ss\x00word\nwith binary \xff bytes")
	if err := v.Put(ctx, name, val); err != nil {
		t.Fatal(err)
	}
	got, err := v.Get(ctx, name)
	if err != nil || !bytes.Equal(got, val) {
		t.Fatalf("round trip: %q %v", got, err)
	}
	if err := v.Put(ctx, name, []byte("second")); err != nil {
		t.Fatal(err)
	}
	if got, _ := v.Get(ctx, name); string(got) != "second" {
		t.Fatalf("overwrite: %q", got)
	}

	// Stored under <mount>/<prefix><name> as {"value": base64}.
	req, _ := http.NewRequest(http.MethodGet, addr+"/v1/secret/data/fortik/"+name, nil)
	req.Header.Set("X-Vault-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(buf.String(), `"value":"c2Vjb25k"`) {
		t.Fatalf("raw KV entry: %d %s", resp.StatusCode, buf.String())
	}

	// Delete removes metadata: all versions gone, and the version history too.
	if err := v.Delete(ctx, name); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Get(ctx, name); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
	req, _ = http.NewRequest(http.MethodGet, addr+"/v1/secret/metadata/fortik/"+name, nil)
	req.Header.Set("X-Vault-Token", token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("metadata still present after delete: %d", resp.StatusCode)
	}
	if err := v.Delete(ctx, name); err != nil {
		t.Fatalf("delete missing: %v", err)
	}
	if err := v.Put(ctx, "../escape", []byte("x")); err == nil {
		t.Fatal("traversal name accepted")
	}

	// Concurrency.
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			n := fmt.Sprintf("c/%d", i)
			if err := v.Put(ctx, n, []byte(n)); err != nil {
				t.Error(err)
				return
			}
			if got, err := v.Get(ctx, n); err != nil || string(got) != n {
				t.Errorf("%s: %q %v", n, got, err)
			}
		}(i)
	}
	wg.Wait()

	// A wrong token is a clear permission error that does not echo the token.
	bad, err := secrets.NewVault(secrets.VaultConfig{Addr: addr, Token: "wrong-token-value"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = bad.Get(ctx, "c/1")
	if err == nil || errors.Is(err, secrets.ErrNotFound) || !strings.Contains(err.Error(), "403") {
		t.Fatalf("bad token: want a 403 error, got %v", err)
	}
	if strings.Contains(err.Error(), "wrong-token-value") || strings.Contains(err.Error(), token) {
		t.Fatal("error leaks a token")
	}
}

func TestVaultTimeoutAndRedirect(t *testing.T) {
	ctx := context.Background()
	// fakeVaultSlow is a local fake that never answers in time.
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer slow.Close()
	v, err := secrets.NewVault(secrets.VaultConfig{Addr: slow.URL, Token: "t0ken", HTTPClient: &http.Client{Timeout: 100 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Get(ctx, "x"); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("want timeout, got %v", err)
	}

	// fakeVaultRedirect is a local fake that redirects to another host; the
	// token must not follow.
	var leaked atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "" {
			leaked.Store(true)
		}
	}))
	defer other.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, strings.Replace(other.URL, "127.0.0.1", "localhost", 1)+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer redir.Close()
	v, _ = secrets.NewVault(secrets.VaultConfig{Addr: redir.URL, Token: "t0ken"})
	if _, err := v.Get(ctx, "x"); err == nil {
		t.Fatal("cross-host redirect followed")
	}
	if leaked.Load() {
		t.Fatal("token sent to the redirect target")
	}
}
