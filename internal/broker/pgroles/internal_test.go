package pgroles

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"fortik/internal/broker"
)

// TestScramVerifierRFC7677 checks StoredKey/ServerKey against the RFC 7677
// SCRAM-SHA-256 exchange (user "user", password "pencil").
func TestScramVerifierRFC7677(t *testing.T) {
	salt, _ := base64.StdEncoding.DecodeString("W22ZaJ0SNY7soEsUEjb6gQ==")
	v, err := scramVerifierWithSalt("pencil", salt, 4096)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(strings.TrimPrefix(v, "SCRAM-SHA-256$4096:W22ZaJ0SNY7soEsUEjb6gQ==$"), ":")
	if len(parts) != 2 {
		t.Fatalf("verifier shape: %s", v)
	}
	storedKey, _ := base64.StdEncoding.DecodeString(parts[0])
	serverKey, _ := base64.StdEncoding.DecodeString(parts[1])
	authMsg := "n=user,r=rOprNGfwEbeRWgbNEkqO," +
		"r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096," +
		"c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"
	if got := base64.StdEncoding.EncodeToString(hmacSHA256(serverKey, authMsg)); got != "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=" {
		t.Fatalf("server signature %s", got)
	}
	// ClientKey = ClientProof XOR ClientSignature; SHA256(ClientKey) must be StoredKey.
	proof, _ := base64.StdEncoding.DecodeString("dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=")
	sig := hmacSHA256(storedKey, authMsg)
	clientKey := make([]byte, len(proof))
	for i := range proof {
		clientKey[i] = proof[i] ^ sig[i]
	}
	if sum := sha256.Sum256(clientKey); !hmac.Equal(sum[:], storedKey) {
		t.Fatal("stored key does not match the RFC client proof")
	}
}

func TestMintUnsupported(t *testing.T) {
	m := &Manager{}
	if _, err := m.Mint(context.Background(), "a", nil, time.Minute); !errors.Is(err, broker.ErrUnsupported) {
		t.Fatalf("Mint: %v", err)
	}
	if m.System() != "postgres" {
		t.Fatal(m.System())
	}
	if _, err := New(Config{}); err == nil {
		t.Fatal("New accepted missing dependencies")
	}
}
