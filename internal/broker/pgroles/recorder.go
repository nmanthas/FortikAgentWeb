package pgroles

import (
	"context"
	"errors"
	"sync/atomic"

	"fortik/internal/broker"
)

// ErrRecorderUnset is returned by a LateRecorder used before Set: no
// credential is issued that cannot be recorded (fail closed).
var ErrRecorderUnset = errors.New("pgroles: issuance recorder not wired yet")

// LateRecorder breaks the construction cycle between the broker and this
// package: broker.New takes its adapters (including the Manager) up front,
// while the Manager needs the broker to record issuances. Pass a LateRecorder
// to New, build the broker with the Manager as its "postgres" adapter, then
// call Set with the broker. Until Set, every issuance is refused.
type LateRecorder struct {
	r atomic.Pointer[Recorder]
}

// Set wires the real recorder (normally the *broker.Service). Set(nil) makes
// issuance fail closed again.
func (l *LateRecorder) Set(r Recorder) {
	if r == nil {
		l.r.Store(nil)
		return
	}
	l.r.Store(&r)
}

// RecordIssuance implements Recorder.
func (l *LateRecorder) RecordIssuance(ctx context.Context, c broker.Credential, agentID, instanceID string) error {
	p := l.r.Load()
	if p == nil {
		return ErrRecorderUnset
	}
	return (*p).RecordIssuance(ctx, c, agentID, instanceID)
}
