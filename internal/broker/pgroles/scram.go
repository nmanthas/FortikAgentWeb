package pgroles

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// scramIterations matches Postgres' default scram_iterations. The passwords
// are 32 random bytes, so the iteration count is not what protects them.
const scramIterations = 4096

// newPassword returns a fresh random password (32 bytes, base64url).
func newPassword() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate password: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// scramVerifier computes the SCRAM-SHA-256 verifier Postgres stores for
// password (RFC 5802/7677, Postgres format
// "SCRAM-SHA-256$<iter>:<salt>$<StoredKey>:<ServerKey>"). Fortik sends the
// verifier, never the plaintext, in ALTER ROLE ... PASSWORD, so the password
// cannot appear in server logs or pg_stat_statements. Postgres accepts a
// pre-hashed verifier as-is. password must be ASCII (SASLprep is identity).
func scramVerifier(password string) (string, error) {
	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	return scramVerifierWithSalt(password, salt[:], scramIterations)
}

func scramVerifierWithSalt(password string, salt []byte, iter int) (string, error) {
	salted, err := pbkdf2.Key(sha256.New, password, salt, iter, sha256.Size)
	if err != nil {
		return "", fmt.Errorf("scram: %w", err)
	}
	clientKey := hmacSHA256(salted, "Client Key")
	storedKey := sha256.Sum256(clientKey)
	serverKey := hmacSHA256(salted, "Server Key")
	enc := base64.StdEncoding
	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s", iter, enc.EncodeToString(salt),
		enc.EncodeToString(storedKey[:]), enc.EncodeToString(serverKey)), nil
}

func hmacSHA256(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return m.Sum(nil)
}
