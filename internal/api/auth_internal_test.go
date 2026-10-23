package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

type flakySecrets struct {
	data []byte
	fail bool
}

func (f *flakySecrets) Get(context.Context, string) ([]byte, error) {
	if f.fail {
		return nil, errors.New("secret store down")
	}
	return f.data, nil
}

// Review finding: a failed reload silently kept the old token set forever,
// masking revocations.
func TestTokenAuthFailsClosedWhenSecretUnreadableTooLong(t *testing.T) {
	sum := sha256.Sum256([]byte("tok"))
	sec := &flakySecrets{data: []byte(`[{"name":"x","sha256":"` + hex.EncodeToString(sum[:]) + `","roles":["auditor"]}]`)}
	a, err := NewTokenAuth(context.Background(), sec, "api_tokens")
	if err != nil {
		t.Fatal(err)
	}
	a.ttl, a.maxStale = time.Millisecond, 50*time.Millisecond
	if _, ok := a.Authenticate(context.Background(), "tok"); !ok {
		t.Fatal("valid token refused")
	}
	sec.fail = true
	time.Sleep(5 * time.Millisecond)
	if _, ok := a.Authenticate(context.Background(), "tok"); !ok {
		t.Fatal("a brief secret-store blip should keep the previous set")
	}
	time.Sleep(60 * time.Millisecond)
	if _, ok := a.Authenticate(context.Background(), "tok"); ok {
		t.Fatal("tokens must be refused once the set is stale beyond maxStale")
	}
	sec.fail = false
	if _, ok := a.Authenticate(context.Background(), "tok"); !ok {
		t.Fatal("must recover once the secret is readable")
	}
}
