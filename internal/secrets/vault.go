package secrets

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"fortik/internal/config"
)

// Environment variables read by the vault store (the same names the Vault
// and OpenBao CLIs use).
const (
	EnvVaultToken     = "VAULT_TOKEN"
	EnvVaultNamespace = "VAULT_NAMESPACE" // optional (Vault Enterprise / OpenBao namespaces)
	EnvVaultCACert    = "VAULT_CACERT"    // optional PEM bundle trusted in addition to the system roots
)

const (
	vaultTimeout  = 10 * time.Second
	vaultMaxResp  = 2 << 20
	vaultErrorCap = 300
)

// VaultConfig configures a Vault/OpenBao KV v2 store.
type VaultConfig struct {
	Addr      string // e.g. https://vault.internal:8200
	Mount     string // KV v2 mount, default "secret"
	Prefix    string // path prefix under the mount, default "fortik/"
	Token     string // never logged or included in errors
	Namespace string
	// HTTPClient overrides the default client (10 s timeout).
	HTTPClient *http.Client
}

// Vault is a writable secret store over the KV v2 HTTP API (no SDK). Each
// secret is the KV entry <mount>/<prefix><name> holding {"value": base64}.
// Delete removes the entry's metadata, i.e. every version.
type Vault struct {
	base      *url.URL
	mount     string
	prefix    string
	token     string
	namespace string
	hc        *http.Client
}

var _ Store = (*Vault)(nil)

// NewVault validates cfg and builds the store. Plain http is refused except
// to a loopback address (the token would otherwise cross the network in
// clear text).
func NewVault(cfg VaultConfig) (*Vault, error) {
	if cfg.Token == "" {
		return nil, fmt.Errorf("vault: no token: set env %s", EnvVaultToken)
	}
	u, err := url.Parse(strings.TrimRight(cfg.Addr, "/"))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("vault: invalid address %q (want scheme://host:port)", cfg.Addr)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !loopbackHost(u.Hostname()) {
			return nil, fmt.Errorf("vault: refusing plain http to non-loopback address %q; use https", cfg.Addr)
		}
	default:
		return nil, fmt.Errorf("vault: invalid address %q (scheme must be https, or http on loopback)", cfg.Addr)
	}
	mount := strings.Trim(cfg.Mount, "/")
	if mount == "" {
		mount = "secret"
	}
	if err := ValidName(mount); err != nil {
		return nil, fmt.Errorf("vault: invalid mount: %w", err)
	}
	prefix := strings.Trim(cfg.Prefix, "/")
	if prefix != "" {
		if err := ValidName(prefix); err != nil {
			return nil, fmt.Errorf("vault: invalid prefix: %w", err)
		}
		prefix += "/"
	}
	hc := &http.Client{Timeout: vaultTimeout}
	if cfg.HTTPClient != nil {
		c := *cfg.HTTPClient
		hc = &c
	}
	// Go forwards custom headers such as X-Vault-Token on redirects; never
	// let a redirect carry the token to another host.
	hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		if req.URL.Scheme != u.Scheme || req.URL.Host != u.Host {
			return errors.New("redirect to a different host refused")
		}
		return nil
	}
	return &Vault{base: u, mount: mount, prefix: prefix, token: cfg.Token, namespace: cfg.Namespace, hc: hc}, nil
}

// OpenVault builds the store from config; the token comes from env
// VAULT_TOKEN, an optional CA bundle from VAULT_CACERT.
func OpenVault(cfg config.SecretsConfig) (*Vault, error) {
	vc := VaultConfig{
		Addr:      cfg.VaultAddr,
		Mount:     cfg.VaultMount,
		Prefix:    cfg.VaultPrefix,
		Token:     strings.TrimSpace(os.Getenv(EnvVaultToken)),
		Namespace: os.Getenv(EnvVaultNamespace),
	}
	if caFile := os.Getenv(EnvVaultCACert); caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("vault: %s: %w", EnvVaultCACert, err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("vault: %s: no PEM certificates found", EnvVaultCACert)
		}
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		vc.HTTPClient = &http.Client{Timeout: vaultTimeout, Transport: tr}
	}
	return NewVault(vc)
}

// String never includes the token.
func (v *Vault) String() string {
	return fmt.Sprintf("vault(%s, mount=%s, prefix=%s)", v.base.Redacted(), v.mount, v.prefix)
}

// GoString keeps %#v from printing the token.
func (v *Vault) GoString() string { return v.String() }

func (v *Vault) endpoint(kind, name string) string {
	segs := strings.Split(v.mount+"/"+kind+"/"+v.prefix+name, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return v.base.String() + "/v1/" + strings.Join(segs, "/")
}

type kvValue struct {
	Value string `json:"value"`
}

// Get reads the latest version. A missing or soft-deleted entry is ErrNotFound.
func (v *Vault) Get(ctx context.Context, name string) ([]byte, error) {
	if err := ValidName(name); err != nil {
		return nil, err
	}
	status, body, err := v.do(ctx, http.MethodGet, v.endpoint("data", name), nil)
	if err != nil {
		return nil, fmt.Errorf("vault: read secret %s: %w", name, err)
	}
	switch {
	case status == http.StatusNotFound:
		return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
	case status != http.StatusOK:
		return nil, fmt.Errorf("vault: read secret %s: %s", name, vaultError(status, body))
	}
	var resp struct {
		Data struct {
			Data *kvValue `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("vault: read secret %s: malformed response", name)
	}
	if resp.Data.Data == nil {
		// KV v2 returns data:null for a deleted latest version.
		return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	val, err := base64.StdEncoding.DecodeString(resp.Data.Data.Value)
	if err != nil {
		return nil, fmt.Errorf("vault: read secret %s: value is not base64 (not written by Fortik?)", name)
	}
	return val, nil
}

// Put writes a new version of the entry.
func (v *Vault) Put(ctx context.Context, name string, value []byte) error {
	if err := ValidName(name); err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]any{"data": kvValue{Value: base64.StdEncoding.EncodeToString(value)}})
	if err != nil {
		return fmt.Errorf("vault: write secret %s: encode: %w", name, err)
	}
	status, body, err := v.do(ctx, http.MethodPost, v.endpoint("data", name), payload)
	if err != nil {
		return fmt.Errorf("vault: write secret %s: %w", name, err)
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return fmt.Errorf("vault: write secret %s: %s", name, vaultError(status, body))
	}
	return nil
}

// Delete removes the entry and all its versions; a missing entry is not an error.
func (v *Vault) Delete(ctx context.Context, name string) error {
	if err := ValidName(name); err != nil {
		return err
	}
	status, body, err := v.do(ctx, http.MethodDelete, v.endpoint("metadata", name), nil)
	if err != nil {
		return fmt.Errorf("vault: delete secret %s: %w", name, err)
	}
	if status != http.StatusOK && status != http.StatusNoContent && status != http.StatusNotFound {
		return fmt.Errorf("vault: delete secret %s: %s", name, vaultError(status, body))
	}
	return nil
}

func (v *Vault) do(ctx context.Context, method, u string, payload []byte) (int, []byte, error) {
	var rd io.Reader
	if payload != nil {
		rd = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return 0, nil, errors.New("build request failed")
	}
	req.Header.Set("X-Vault-Token", v.token)
	req.Header.Set("X-Vault-Request", "true")
	if v.namespace != "" {
		req.Header.Set("X-Vault-Namespace", v.namespace)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := v.hc.Do(req)
	if err != nil {
		return 0, nil, transportError(ctx, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, vaultMaxResp+1))
	if err != nil {
		return 0, nil, transportError(ctx, err)
	}
	if len(body) > vaultMaxResp {
		return 0, nil, errors.New("response too large")
	}
	return resp.StatusCode, body, nil
}

// transportError reduces an HTTP client error to a token-free description
// (url.Error carries the URL, which never contains the token, but keep the
// message short and stable anyway).
func transportError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return errors.New("request timed out")
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("request failed: %v", ue.Err)
	}
	return errors.New("request failed")
}

func vaultError(status int, body []byte) string {
	var e struct {
		Errors []string `json:"errors"`
	}
	msg := ""
	if json.Unmarshal(body, &e) == nil && len(e.Errors) > 0 {
		msg = strings.Join(e.Errors, "; ")
	}
	if status == http.StatusForbidden && msg == "" {
		msg = "permission denied (check the token and its policy)"
	}
	if len(msg) > vaultErrorCap {
		msg = msg[:vaultErrorCap] + "..."
	}
	if msg == "" {
		return fmt.Sprintf("status %d", status)
	}
	return fmt.Sprintf("status %d: %s", status, msg)
}

func loopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}
