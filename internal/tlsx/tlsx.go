// Package tlsx builds the TLS (and mutual TLS) configurations of Fortik's
// listeners and clients (Phase 6: "mTLS between components").
//
// A listener with a certificate serves TLS 1.2+. With client_auth "require"
// every client must present a certificate signed by client_ca_file: the API,
// the app gateway (and the hook endpoint on it), the agentgateway callout and
// the Postgres proxy then refuse any caller without one. Bearer tokens are
// still checked on top (defense in depth).
package tlsx

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"fortik/internal/config"
)

// Client-auth modes (config tls.client_auth).
const (
	ClientAuthNone    = "none"
	ClientAuthRequest = "request" // verify a certificate when one is sent
	ClientAuthRequire = "require" // mutual TLS: a verified certificate is mandatory
)

// Enabled reports whether the listener serves TLS.
func Enabled(c config.TLSConfig) bool { return c.CertFile != "" || c.KeyFile != "" }

// Server returns the listener's TLS configuration (nil when TLS is off).
func Server(c config.TLSConfig) (*tls.Config, error) {
	if !Enabled(c) {
		if c.ClientCAFile != "" || (c.ClientAuth != "" && c.ClientAuth != ClientAuthNone) {
			return nil, errors.New("tls: client_ca_file / client_auth need cert_file and key_file")
		}
		return nil, nil
	}
	if c.CertFile == "" || c.KeyFile == "" {
		return nil, errors.New("tls: cert_file and key_file must be set together")
	}
	cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("tls: load key pair: %w", err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	mode := c.ClientAuth
	if mode == "" {
		mode = ClientAuthNone
		if c.ClientCAFile != "" {
			mode = ClientAuthRequire
		}
	}
	switch mode {
	case ClientAuthNone:
		if c.ClientCAFile != "" {
			return nil, errors.New("tls: client_ca_file set with client_auth none")
		}
	case ClientAuthRequest, ClientAuthRequire:
		if c.ClientCAFile == "" {
			return nil, fmt.Errorf("tls: client_auth %s needs client_ca_file", mode)
		}
		pool, err := loadPool(c.ClientCAFile)
		if err != nil {
			return nil, err
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
		if mode == ClientAuthRequire {
			cfg.ClientAuth = tls.RequireAndVerifyClientCert
		}
	default:
		return nil, fmt.Errorf("tls: client_auth must be none, request or require, got %q", mode)
	}
	return cfg, nil
}

// Client returns a client configuration that trusts caFile (system roots when
// empty) and presents certFile/keyFile when given.
func Client(caFile, certFile, keyFile string) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pool, err := loadPool(caFile)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = pool
	}
	if (certFile == "") != (keyFile == "") {
		return nil, errors.New("tls: client certificate and key must be set together")
	}
	if certFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("tls: load client key pair: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

func loadPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("tls: read CA %s: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("tls: no certificates in %s", path)
	}
	return pool, nil
}
