package delegation

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Token format (compact, URL-safe, no padding):
//
//	base64url(JSON claims) "." base64url(HMAC-SHA256(key, "fortik-delegation-v1." + base64url(JSON claims)))
//
// The MAC covers the encoded claims exactly as transmitted, with a domain
// prefix so the key can never validate another kind of message. Tokens are
// bearer secrets: they are never logged, stored or written to the Diary.

const (
	macDomain = "fortik-delegation-v1."
	// MinKeyLen is the minimum HMAC key length accepted (256 bits).
	MinKeyLen = 32
	// MaxTokenLen bounds what Verify will even look at.
	MaxTokenLen = 8 << 10
	// MaxChainLen bounds the agents a chain may carry (as action.Chain).
	MaxChainLen = 64
	maxTaskLen  = 256
)

// signer holds the HMAC key. It has no exported fields and prints nothing.
type signer struct{ key []byte }

func newSigner(key []byte) (*signer, error) {
	if len(key) < MinKeyLen {
		return nil, fmt.Errorf("delegation: signing key must be at least %d bytes (got %d)", MinKeyLen, len(key))
	}
	return &signer{key: bytes.Clone(key)}, nil
}

func (s *signer) String() string   { return "delegation.signer(redacted)" }
func (s *signer) GoString() string { return s.String() }

func (s *signer) mac(payload string) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(macDomain))
	m.Write([]byte(payload))
	return m.Sum(nil)
}

// sign encodes and signs claims.
func (s *signer) sign(c Claims) (string, error) {
	if err := c.validate(); err != nil {
		return "", err
	}
	b, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("delegation: encode claims: %w", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(b)
	return payload + "." + base64.RawURLEncoding.EncodeToString(s.mac(payload)), nil
}

// verify checks the MAC (constant time), then the claims' shape, expiry and
// holder, in that order: nothing about an unauthenticated token is trusted,
// so a forged token is always ErrInvalidToken, never "expired" or "wrong agent".
func (s *signer) verify(token, holder string, now time.Time) (Claims, error) {
	if token == "" || len(token) > MaxTokenLen {
		return Claims{}, ErrInvalidToken
	}
	payload, sig, ok := strings.Cut(token, ".")
	if !ok || payload == "" || sig == "" || strings.Contains(sig, ".") {
		return Claims{}, ErrInvalidToken
	}
	got, err := base64.RawURLEncoding.Strict().DecodeString(sig)
	if err != nil || len(got) != sha256.Size {
		return Claims{}, ErrInvalidToken
	}
	if !hmac.Equal(got, s.mac(payload)) {
		return Claims{}, ErrInvalidToken
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(payload)
	if err != nil {
		return Claims{}, ErrInvalidToken
	}
	var c Claims
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil || dec.More() {
		return Claims{}, ErrInvalidToken
	}
	if err := c.validate(); err != nil {
		return Claims{}, ErrInvalidToken
	}
	if !now.Before(c.ExpiresAt) {
		return Claims{}, ErrExpiredToken
	}
	if holder == "" || c.Chain[len(c.Chain)-1] != holder {
		return Claims{}, ErrTokenAgent
	}
	return c, nil
}

// validate checks the claims' internal consistency. Depth is the number of
// hops from the root; a chain inferred from several open delegations may
// carry more agents than depth+1 (the union of every upstream agent).
func (c Claims) validate() error {
	switch {
	case c.DelegationID == "":
		return fmt.Errorf("%w: no delegation id", ErrInvalidToken)
	case len(c.Chain) < 2 || len(c.Chain) > MaxChainLen:
		return fmt.Errorf("%w: chain must have 2..%d agents", ErrInvalidToken, MaxChainLen)
	case c.Root != c.Chain[0]:
		return fmt.Errorf("%w: root is not the first chain element", ErrInvalidToken)
	case c.Depth < 1 || c.Depth > len(c.Chain)-1:
		return fmt.Errorf("%w: depth out of range", ErrInvalidToken)
	case len(c.TaskID) > maxTaskLen:
		return fmt.Errorf("%w: task id too long", ErrInvalidToken)
	case c.IssuedAt.IsZero() || !c.ExpiresAt.After(c.IssuedAt):
		return fmt.Errorf("%w: bad validity window", ErrInvalidToken)
	}
	for _, a := range c.Chain {
		if !agentIDPattern.MatchString(a) {
			return fmt.Errorf("%w: malformed agent id in chain", ErrInvalidToken)
		}
	}
	return nil
}
