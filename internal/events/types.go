// Package events carries committed Diary entries to live consumers (console
// SSE). The Diary is the outbox: a tailer publishes only committed entries.
package events

import (
	"context"
	"encoding/json"
	"time"
)

// Event is one committed Diary entry as published on the bus.
type Event struct {
	Seq       int64           `json:"seq"`
	TS        time.Time       `json:"ts"`
	AgentID   string          `json:"agent_id,omitempty"`
	EventType string          `json:"event_type"`
	Data      json.RawMessage `json:"data"`
}

// Bus publishes and fans out events. Implementations: memory, nats (JetStream).
type Bus interface {
	Publish(ctx context.Context, e Event) error
	// Subscribe delivers events with seq > afterSeq (best effort replay for
	// JetStream; memory replays from its ring buffer) until ctx ends.
	Subscribe(ctx context.Context, afterSeq int64) (<-chan Event, error)
	Close() error
}
