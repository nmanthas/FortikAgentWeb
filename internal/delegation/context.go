package delegation

import (
	"context"
	"strings"
	"sync"

	"fortik/internal/decide"
)

// Transports (gateway, hook, agentgw, pgproxy) hand delegation tokens to and
// from Decide through the request context, so a token never travels inside
// the Action (which is stored and written to the Diary).
//
//	ctx = delegation.WithToken(ctx, r.Header.Get(delegation.Header)) // inbound token, if any
//	ctx, sink := delegation.WithTokenSink(ctx)                        // only for DELEGATE actions
//	out, err := decider.Decide(ctx, a)
//	if tok, hop, ok := sink.TokenFor(out); ok { /* forward tok as X-Fortik-Delegation */ }

type tokenKey struct{}

type sinkKey struct{}

// WithToken attaches the delegation token the acting agent presented
// (surrounding whitespace is ignored; an empty token attaches nothing). The
// delegation enricher verifies it; an invalid token is refused (POL-604),
// never ignored.
func WithToken(ctx context.Context, token string) context.Context {
	token = strings.TrimSpace(token)
	if token == "" {
		return ctx
	}
	return context.WithValue(ctx, tokenKey{}, token)
}

// TokenFrom returns the token attached by WithToken.
func TokenFrom(ctx context.Context) (string, bool) {
	t, ok := ctx.Value(tokenKey{}).(string)
	return t, ok && t != ""
}

// Sink receives the token for a hop the delegation observer opened while
// deciding an allowed DELEGATE. It is written inside the decision
// transaction, so read it only through TokenFor, which checks that the
// decision actually committed as executable for this very action.
type Sink struct {
	mu    sync.Mutex
	token string
	hop   Hop
	set   bool
}

// WithTokenSink returns a context carrying a fresh Sink.
func WithTokenSink(ctx context.Context) (context.Context, *Sink) {
	s := &Sink{}
	return context.WithValue(ctx, sinkKey{}, s), s
}

func sinkFrom(ctx context.Context) *Sink {
	s, _ := ctx.Value(sinkKey{}).(*Sink)
	return s
}

func (s *Sink) put(token string, h Hop) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.token, s.hop, s.set = token, h, true
}

// TokenFor returns the token and hop recorded for the decided action. ok is
// false unless the decision executes, did not fail closed, and the hop was
// opened by that same action (a rolled-back or refused decision never
// releases a token).
func (s *Sink) TokenFor(out decide.Outcome) (token string, hop Hop, ok bool) {
	if s == nil || !out.Result.Decision.Executes() || out.FailClosed || out.Action.ActionID == "" {
		return "", Hop{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.set || s.hop.ActionID != out.Action.ActionID {
		return "", Hop{}, false
	}
	return s.token, s.hop, true
}

// String and GoString never reveal the token.
func (s *Sink) String() string   { return "delegation.Sink(redacted)" }
func (s *Sink) GoString() string { return s.String() }

// MarshalJSON never reveals the token.
func (s *Sink) MarshalJSON() ([]byte, error) { return []byte(`"redacted"`), nil }
