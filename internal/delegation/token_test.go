package delegation

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

func testSigner(t *testing.T, b byte) *signer {
	t.Helper()
	s, err := newSigner(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func claims() Claims {
	return Claims{DelegationID: "dlg_1", Root: "agent_a", Chain: []string{"agent_a", "agent_b", "agent_c"}, Depth: 2,
		TaskID: "task-9", IssuedAt: t0, ExpiresAt: t0.Add(15 * time.Minute)}
}

func TestTokenRoundTrip(t *testing.T) {
	s := testSigner(t, 1)
	tok, err := s.sign(claims())
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(tok, "+/=") || strings.Count(tok, ".") != 1 {
		t.Fatalf("token is not compact base64url: %q", tok)
	}
	got, err := s.verify(tok, "agent_c", t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	want := claims()
	if got.DelegationID != want.DelegationID || got.Root != want.Root || got.Depth != 2 || got.TaskID != "task-9" ||
		strings.Join(got.Chain, ",") != "agent_a,agent_b,agent_c" || !got.ExpiresAt.Equal(want.ExpiresAt) || !got.IssuedAt.Equal(t0) {
		t.Fatalf("claims: %+v", got)
	}
}

func TestTokenExpiryAndHolder(t *testing.T) {
	s := testSigner(t, 1)
	tok, _ := s.sign(claims())
	if _, err := s.verify(tok, "agent_c", t0.Add(15*time.Minute)); !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("at exp: %v", err)
	}
	if _, err := s.verify(tok, "agent_c", t0.Add(time.Hour)); !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("after exp: %v", err)
	}
	for _, holder := range []string{"agent_b", "agent_a", "", "AGENT_C"} {
		if _, err := s.verify(tok, holder, t0); !errors.Is(err, ErrTokenAgent) {
			t.Fatalf("holder %q: %v", holder, err)
		}
	}
}

func TestTokenTamper(t *testing.T) {
	s := testSigner(t, 1)
	tok, _ := s.sign(claims())
	payload, sig, _ := strings.Cut(tok, ".")

	// Re-encode modified claims under the original signature.
	forge := func(mut func(map[string]any)) string {
		raw, _ := base64.RawURLEncoding.DecodeString(payload)
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		mut(m)
		b, _ := json.Marshal(m)
		return base64.RawURLEncoding.EncodeToString(b) + "." + sig
	}
	flip := func(s string, i int) string {
		b := []byte(s)
		if b[i] == 'A' {
			b[i] = 'B'
		} else {
			b[i] = 'A'
		}
		return string(b)
	}
	cases := map[string]string{
		"empty":            "",
		"no dot":           payload + sig,
		"two dots":         tok + ".x",
		"payload byte":     flip(payload, 5) + "." + sig,
		"sig byte":         payload + "." + flip(sig, 3),
		"sig truncated":    payload + "." + sig[:len(sig)-2],
		"swapped":          sig + "." + payload,
		"padded":           tok + "=",
		"chain shortened":  forge(func(m map[string]any) { m["chain"] = []string{"agent_b", "agent_c"} }),
		"root removed":     forge(func(m map[string]any) { m["chain"] = []string{"agent_c"} }),
		"expiry extended":  forge(func(m map[string]any) { m["exp"] = t0.Add(48 * time.Hour) }),
		"holder swapped":   forge(func(m map[string]any) { m["chain"] = []string{"agent_a", "agent_b", "agent_x"} }),
		"huge":             strings.Repeat("A", MaxTokenLen+1),
		"other key":        mustSign(t, testSigner(t, 2), claims()),
		"unsigned payload": payload + ".",
	}
	for name, tok := range cases {
		if _, err := s.verify(tok, "agent_c", t0); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s: want ErrInvalidToken, got %v", name, err)
		}
	}
	// A forged token is invalid even when it is also expired or for another
	// holder: unauthenticated claims are never interpreted.
	if _, err := s.verify(cases["other key"], "agent_b", t0.Add(time.Hour)); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("forged+expired+wrong holder: %v", err)
	}
}

func TestTokenRejectsUnknownClaimsAndBadShapes(t *testing.T) {
	s := testSigner(t, 1)
	signRaw := func(v any) string {
		b, _ := json.Marshal(v)
		p := base64.RawURLEncoding.EncodeToString(b)
		return p + "." + base64.RawURLEncoding.EncodeToString(s.mac(p))
	}
	base := map[string]any{"did": "dlg_1", "root": "agent_a", "chain": []string{"agent_a", "agent_b"}, "depth": 1,
		"iat": t0, "exp": t0.Add(time.Minute)}
	if _, err := s.verify(signRaw(base), "agent_b", t0); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	bad := []func(map[string]any){
		func(m map[string]any) { m["admin"] = true },
		func(m map[string]any) { m["root"] = "agent_b" },
		func(m map[string]any) { m["depth"] = 0 },
		func(m map[string]any) { m["depth"] = 2 },
		func(m map[string]any) { m["did"] = "" },
		func(m map[string]any) { m["chain"] = []string{"agent_a", "bad agent"} },
		func(m map[string]any) { m["exp"] = t0 },
		func(m map[string]any) { delete(m, "iat") },
	}
	for i, mut := range bad {
		m := map[string]any{}
		for k, v := range base {
			m[k] = v
		}
		mut(m)
		if _, err := s.verify(signRaw(m), "agent_b", t0); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("case %d: %v", i, err)
		}
	}
}

func TestSignerNeverPrintsKey(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	s, err := newSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{fmt.Sprint(s), fmt.Sprintf("%v %+v %#v", s, s, s)} {
		if strings.Contains(out, "BBBB") || strings.Contains(out, "66 66") {
			t.Fatalf("key leaked: %s", out)
		}
	}
	if _, err := newSigner(key[:31]); err == nil {
		t.Fatal("short key accepted")
	}
}

func mustSign(t *testing.T, s *signer, c Claims) string {
	t.Helper()
	tok, err := s.sign(c)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}
