package secrets_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"fortik/internal/config"
	"fortik/internal/secrets"
)

func newKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, secrets.MasterKeySize)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func newEncFile(t *testing.T) (*secrets.EncFile, string, []byte) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "secrets")
	key := newKey(t)
	s, err := secrets.NewEncFile(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	return s, dir, key
}

func TestEncFileRoundTrip(t *testing.T) {
	s, dir, _ := newEncFile(t)
	ctx := context.Background()
	if _, err := s.Get(ctx, "integration/github/private_key_pem"); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("missing secret: want ErrNotFound, got %v", err)
	}
	val := []byte("-----BEGIN RSA PRIVATE KEY-----\nsuper secret\n-----END RSA PRIVATE KEY-----\n")
	if err := s.Put(ctx, "integration/github/private_key_pem", val); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, "integration/github/private_key_pem")
	if err != nil || !bytes.Equal(got, val) {
		t.Fatalf("round trip: %q %v", got, err)
	}
	// Overwrite.
	if err := s.Put(ctx, "integration/github/private_key_pem", []byte("v2")); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Get(ctx, "integration/github/private_key_pem"); string(got) != "v2" {
		t.Fatalf("overwrite: %q", got)
	}
	// Empty values are allowed by the store (callers decide policy).
	if err := s.Put(ctx, "empty", nil); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Get(ctx, "empty"); err != nil || len(got) != 0 {
		t.Fatalf("empty: %q %v", got, err)
	}

	// On disk: ciphertext only, mode 0600, directories 0700, no temp files left.
	p := filepath.Join(dir, "integration", "github", "private_key_pem.enc")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("v2")) || !bytes.HasPrefix(raw, []byte("FKS\x01")) {
		t.Fatalf("file is not encrypted with the v1 header: %q", raw)
	}
	assertMode(t, p, 0o600)
	assertMode(t, filepath.Join(dir, "integration"), 0o700)
	assertMode(t, filepath.Join(dir, "integration", "github"), 0o700)
	assertMode(t, dir, 0o700)
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if strings.HasPrefix(d.Name(), ".fortik-tmp-") {
			t.Errorf("temp file left behind: %s", path)
		}
		return nil
	})

	// Two writes of the same value use different nonces.
	if err := s.Put(ctx, "a", []byte("same")); err != nil {
		t.Fatal(err)
	}
	c1, _ := os.ReadFile(filepath.Join(dir, "a.enc"))
	if err := s.Put(ctx, "a", []byte("same")); err != nil {
		t.Fatal(err)
	}
	c2, _ := os.ReadFile(filepath.Join(dir, "a.enc"))
	if bytes.Equal(c1, c2) {
		t.Fatal("nonce reused: identical ciphertexts for two writes")
	}

	// Delete, and delete of a missing secret.
	if err := s.Delete(ctx, "integration/github/private_key_pem"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "integration/github/private_key_pem"); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
	if err := s.Delete(ctx, "integration/github/private_key_pem"); err != nil {
		t.Fatalf("delete missing: %v", err)
	}
	if err := s.Delete(ctx, "never/existed/here"); err != nil {
		t.Fatalf("delete missing nested: %v", err)
	}
}

func assertMode(t *testing.T, p string, want os.FileMode) {
	t.Helper()
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != want {
		t.Errorf("%s: mode %v, want %v", p, st.Mode().Perm(), want)
	}
}

func TestEncFileTamperDetected(t *testing.T) {
	s, dir, _ := newEncFile(t)
	ctx := context.Background()
	if err := s.Put(ctx, "k", []byte("value-123")); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "k.enc")
	orig, _ := os.ReadFile(p)
	for i := range orig {
		b := append([]byte{}, orig...)
		b[i] ^= 0x01
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := s.Get(ctx, "k")
		if err == nil {
			t.Fatalf("flipping byte %d went undetected", i)
		}
		if i != 3 && !errors.Is(err, secrets.ErrDecrypt) { // byte 3 is the version: "unsupported version"
			t.Fatalf("byte %d: want ErrDecrypt, got %v", i, err)
		}
		if strings.Contains(err.Error(), "value-123") {
			t.Fatal("error leaks the value")
		}
	}
	// Truncated and garbage files.
	for _, b := range [][]byte{orig[:10], {}, []byte("plaintext secret")} {
		_ = os.WriteFile(p, b, 0o600)
		if _, err := s.Get(ctx, "k"); !errors.Is(err, secrets.ErrDecrypt) {
			t.Fatalf("garbage %q: want ErrDecrypt, got %v", b, err)
		}
	}
}

func TestEncFileWrongKey(t *testing.T) {
	s, dir, _ := newEncFile(t)
	ctx := context.Background()
	if err := s.Put(ctx, "k", []byte("v")); err != nil {
		t.Fatal(err)
	}
	other, err := secrets.NewEncFile(dir, newKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Get(ctx, "k"); !errors.Is(err, secrets.ErrDecrypt) {
		t.Fatalf("wrong key: want ErrDecrypt, got %v", err)
	}
	if _, err := secrets.NewEncFile(dir, []byte("short")); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestEncFileAADBindsName(t *testing.T) {
	s, dir, _ := newEncFile(t)
	ctx := context.Background()
	if err := s.Put(ctx, "integration/aws/secret_access_key", []byte("aws-secret")); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, "integration/aws/external_id", []byte("ext")); err != nil {
		t.Fatal(err)
	}
	// An attacker with file access swaps the two files.
	a := filepath.Join(dir, "integration", "aws", "secret_access_key.enc")
	b := filepath.Join(dir, "integration", "aws", "external_id.enc")
	ab, _ := os.ReadFile(a)
	bb, _ := os.ReadFile(b)
	_ = os.WriteFile(a, bb, 0o600)
	_ = os.WriteFile(b, ab, 0o600)
	for _, n := range []string{"integration/aws/secret_access_key", "integration/aws/external_id"} {
		if _, err := s.Get(ctx, n); !errors.Is(err, secrets.ErrDecrypt) {
			t.Fatalf("%s after swap: want ErrDecrypt, got %v", n, err)
		}
	}
}

func TestEncFileRejectsBadNames(t *testing.T) {
	s, dir, _ := newEncFile(t)
	ctx := context.Background()
	bad := []string{
		"", "..", "../x", "a/../../x", "a/..", "/etc/passwd", "a//b", "a/", ".hidden", "a/.fortik-tmp-1",
		"a\x00b", "a b", "a\\b", "c:x", strings.Repeat("a", secrets.MaxNameLen+1), "a/./b", "./a",
	}
	for _, n := range bad {
		if err := s.Put(ctx, n, []byte("x")); err == nil {
			t.Errorf("Put(%q) accepted", n)
		}
		if _, err := s.Get(ctx, n); err == nil || errors.Is(err, secrets.ErrNotFound) {
			t.Errorf("Get(%q): want invalid-name error, got %v", n, err)
		}
		if err := s.Delete(ctx, n); err == nil {
			t.Errorf("Delete(%q) accepted", n)
		}
	}
	// Nothing escaped the directory.
	parent := filepath.Dir(dir)
	entries, _ := os.ReadDir(parent)
	if len(entries) != 1 {
		t.Fatalf("files written outside the store dir: %v", entries)
	}
	for _, n := range []string{"agent_tokens", "integration/postgres/acme_prod/admin_password", "a.b-c_d/E9"} {
		if err := s.Put(ctx, n, []byte("x")); err != nil {
			t.Errorf("Put(%q): %v", n, err)
		}
	}
}

func TestEncFileConcurrent(t *testing.T) {
	s, _, _ := newEncFile(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 200)
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				shared := "shared/key"
				own := fmt.Sprintf("worker/%d/%d", w, i)
				val := []byte(fmt.Sprintf("w%d-i%d", w, i))
				if err := s.Put(ctx, shared, val); err != nil {
					errs <- err
					return
				}
				if err := s.Put(ctx, own, val); err != nil {
					errs <- err
					return
				}
				got, err := s.Get(ctx, shared)
				if err != nil {
					errs <- fmt.Errorf("concurrent read of shared: %w", err) // must never see a torn file
					return
				}
				if !bytes.HasPrefix(got, []byte("w")) {
					errs <- fmt.Errorf("torn value %q", got)
					return
				}
				if got, err := s.Get(ctx, own); err != nil || !bytes.Equal(got, val) {
					errs <- fmt.Errorf("own key: %q %v", got, err)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestLoadMasterKey(t *testing.T) {
	key := newKey(t)
	b64 := base64.StdEncoding.EncodeToString(key)
	dir := t.TempDir()

	t.Setenv(secrets.EnvMasterKey, "")
	if _, err := secrets.LoadMasterKey(config.SecretsConfig{}); err == nil {
		t.Fatal("no key source accepted")
	}

	kf := filepath.Join(dir, "master.key")
	if err := os.WriteFile(kf, []byte(b64+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := secrets.LoadMasterKey(config.SecretsConfig{MasterKeyFile: kf})
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("key file: %v", err)
	}
	if err := os.Chmod(kf, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := secrets.LoadMasterKey(config.SecretsConfig{MasterKeyFile: kf}); err == nil {
		t.Fatal("world-readable key file accepted")
	}

	t.Setenv(secrets.EnvMasterKey, b64)
	got, err = secrets.LoadMasterKey(config.SecretsConfig{MasterKeyFile: "/nonexistent"})
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("env key must take precedence: %v", err)
	}
	t.Setenv(secrets.EnvMasterKey, base64.StdEncoding.EncodeToString(key[:16]))
	if _, err := secrets.LoadMasterKey(config.SecretsConfig{}); err == nil || !strings.Contains(err.Error(), "32 bytes") {
		t.Fatalf("16-byte key: %v", err)
	}
	t.Setenv(secrets.EnvMasterKey, "not base64 !!!")
	if _, err := secrets.LoadMasterKey(config.SecretsConfig{}); err == nil {
		t.Fatal("non-base64 key accepted")
	} else if strings.Contains(err.Error(), "not base64 !!!") {
		t.Fatal("error echoes key material")
	}
}

func TestOpen(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(secrets.EnvMasterKey, base64.StdEncoding.EncodeToString(newKey(t)))
	p, err := secrets.Open(config.SecretsConfig{Provider: "encfile", Dir: filepath.Join(dir, "enc")})
	if err != nil {
		t.Fatal(err)
	}
	if !secrets.Writable(p) {
		t.Fatal("encfile must be writable")
	}
	st := secrets.AsStore(p)
	if err := st.Put(context.Background(), "x", []byte("1")); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "plain"), []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fp, err := secrets.Open(config.SecretsConfig{Provider: "file", Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if secrets.Writable(fp) {
		t.Fatal("file provider must be read-only")
	}
	if v, err := fp.Get(context.Background(), "plain"); err != nil || string(v) != "hello" {
		t.Fatalf("file get: %q %v", v, err)
	}
	if err := secrets.AsStore(fp).Put(context.Background(), "x", []byte("1")); !errors.Is(err, secrets.ErrReadOnly) {
		t.Fatalf("read-only put: %v", err)
	}
	if err := secrets.AsStore(secrets.Env{}).Delete(context.Background(), "x"); !errors.Is(err, secrets.ErrReadOnly) {
		t.Fatalf("read-only delete: %v", err)
	}
	if _, err := secrets.Open(config.SecretsConfig{Provider: "env"}); err != nil {
		t.Fatal(err)
	}
	if _, err := secrets.Open(config.SecretsConfig{Provider: "bogus"}); err == nil {
		t.Fatal("unknown provider accepted")
	}
	t.Setenv(secrets.EnvVaultToken, "")
	if _, err := secrets.Open(config.SecretsConfig{Provider: "vault", VaultAddr: "http://127.0.0.1:1"}); err == nil {
		t.Fatal("vault without token accepted")
	}
	t.Setenv(secrets.EnvVaultToken, "tok")
	if _, err := secrets.Open(config.SecretsConfig{Provider: "vault", VaultAddr: "http://vault.example.com:8200"}); err == nil {
		t.Fatal("plain http to a remote vault accepted")
	}
	// Legacy constructor keeps working.
	if _, err := secrets.New("file", dir); err != nil {
		t.Fatal(err)
	}
}
