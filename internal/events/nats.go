package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	// StreamName is the JetStream stream holding Diary events.
	StreamName = "FORTIK"
	// SubjectPrefix prefixes every subject: fortik.diary.<event_type>.
	SubjectPrefix = "fortik.diary."
	subjectAll    = SubjectPrefix + ">"
	// headerSeq carries the Diary seq so replay can locate a position
	// without decoding every payload.
	headerSeq = "Fortik-Seq"
)

// NATSOptions tunes the JetStream stream.
type NATSOptions struct {
	MaxAge     time.Duration // retention (default 24h)
	MaxMsgs    int64         // retention cap (default 100000)
	Duplicates time.Duration // Nats-Msg-Id dedupe window (default 2m)
	Log        *slog.Logger
}

// NATSBus publishes to JetStream stream FORTIK, subject
// fortik.diary.<event_type>, with Nats-Msg-Id = the Diary seq so a re-publish
// (tailer retry, a second replica) is deduplicated by the server.
type NATSBus struct {
	nc  *nats.Conn
	js  jetstream.JetStream
	str jetstream.Stream
	log *slog.Logger

	mu     sync.Mutex
	closed bool
	stops  map[*natsSub]struct{}
}

type natsSub struct {
	cc   jetstream.ConsumeContext
	ch   chan Event
	once sync.Once
}

// NewNATSBus connects to url and creates or updates the stream.
func NewNATSBus(ctx context.Context, url string, o NATSOptions) (*NATSBus, error) {
	if url == "" {
		return nil, errors.New("events: nats url is required")
	}
	if o.MaxAge <= 0 {
		o.MaxAge = 24 * time.Hour
	}
	if o.MaxMsgs <= 0 {
		o.MaxMsgs = 100000
	}
	if o.Duplicates <= 0 {
		o.Duplicates = 2 * time.Minute
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	nc, err := nats.Connect(url, nats.Name("fortik"), nats.MaxReconnects(-1), nats.ReconnectWait(time.Second))
	if err != nil {
		return nil, fmt.Errorf("events: connect nats: %w", err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("events: jetstream: %w", err)
	}
	str, err := js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:       StreamName,
		Subjects:   []string{subjectAll},
		Storage:    jetstream.FileStorage,
		Retention:  jetstream.LimitsPolicy,
		Discard:    jetstream.DiscardOld,
		MaxAge:     o.MaxAge,
		MaxMsgs:    o.MaxMsgs,
		Duplicates: o.Duplicates,
	})
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("events: create stream %s: %w", StreamName, err)
	}
	return &NATSBus{nc: nc, js: js, str: str, log: o.Log, stops: map[*natsSub]struct{}{}}, nil
}

// Subject returns the subject for an event type. Each dot-separated token
// keeps [A-Za-z0-9_-]; anything else (including the NATS wildcards * and >)
// becomes '_', and an empty token becomes '_', so a subject is always valid.
func Subject(eventType string) string {
	if eventType == "" {
		return SubjectPrefix + "unknown"
	}
	toks := strings.Split(eventType, ".")
	for i, t := range toks {
		b := []byte(t)
		for k, c := range b {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
				b[k] = '_'
			}
		}
		if len(b) == 0 {
			b = []byte{'_'}
		}
		toks[i] = string(b)
	}
	return SubjectPrefix + strings.Join(toks, ".")
}

func (b *NATSBus) Publish(ctx context.Context, e Event) error {
	b.mu.Lock()
	closed := b.closed
	b.mu.Unlock()
	if closed {
		return ErrClosed
	}
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	seq := strconv.FormatInt(e.Seq, 10)
	msg := &nats.Msg{Subject: Subject(e.EventType), Data: data, Header: nats.Header{}}
	msg.Header.Set(headerSeq, seq)
	if _, err := b.js.PublishMsg(ctx, msg, jetstream.WithMsgID(seq), jetstream.WithExpectStream(StreamName)); err != nil {
		return fmt.Errorf("events: publish seq %s: %w", seq, err)
	}
	return nil
}

// Subscribe replays retained events with seq > afterSeq (best effort: the
// stream keeps MaxAge/MaxMsgs) and then delivers live ones. A subscriber
// that falls behind is dropped (channel closed), never allowed to block.
func (b *NATSBus) Subscribe(ctx context.Context, afterSeq int64) (<-chan Event, error) {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil, ErrClosed
	}
	b.mu.Unlock()

	start, err := b.startSeq(ctx, afterSeq)
	if err != nil {
		return nil, err
	}
	cfg := jetstream.OrderedConsumerConfig{FilterSubjects: []string{subjectAll}, DeliverPolicy: jetstream.DeliverNewPolicy}
	if start > 0 {
		cfg.DeliverPolicy, cfg.OptStartSeq = jetstream.DeliverByStartSequencePolicy, start
	}
	cons, err := b.str.OrderedConsumer(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("events: consumer: %w", err)
	}
	s := &natsSub{ch: make(chan Event, subscriberBuffer)}
	var mu sync.Mutex // serialises the handler against drop
	last := afterSeq
	dropped := false
	drop := func() {
		s.once.Do(func() {
			if s.cc != nil {
				s.cc.Stop()
			}
			mu.Lock()
			dropped = true
			close(s.ch)
			mu.Unlock()
			b.mu.Lock()
			delete(b.stops, s)
			b.mu.Unlock()
		})
	}
	cc, err := cons.Consume(func(m jetstream.Msg) {
		var e Event
		if err := json.Unmarshal(m.Data(), &e); err != nil {
			b.log.Warn("events: undecodable message on stream", "subject", m.Subject(), "err", err)
			return
		}
		mu.Lock()
		if dropped || e.Seq <= last {
			mu.Unlock()
			return
		}
		select {
		case s.ch <- e:
			last = e.Seq
			mu.Unlock()
		default:
			mu.Unlock()
			go drop() // Stop must not be called from the handler goroutine synchronously.
		}
	})
	if err != nil {
		return nil, fmt.Errorf("events: consume: %w", err)
	}
	s.cc = cc
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		drop()
		return nil, ErrClosed
	}
	b.stops[s] = struct{}{}
	b.mu.Unlock()
	go func() {
		select {
		case <-ctx.Done():
		case <-cc.Closed():
		}
		drop()
	}()
	return s.ch, nil
}

// startSeq finds the first stream sequence whose Diary seq is > afterSeq by
// binary search over the retained range (stream order follows Diary order
// because a single tailer publishes in seq order). 0 means "only new".
func (b *NATSBus) startSeq(ctx context.Context, afterSeq int64) (uint64, error) {
	info, err := b.str.Info(ctx)
	if err != nil {
		return 0, fmt.Errorf("events: stream info: %w", err)
	}
	st := info.State
	if st.Msgs == 0 {
		// Empty stream: everything published from now on is > afterSeq
		// (or a duplicate the consumer filters).
		return st.LastSeq + 1, nil
	}
	lo, hi := st.FirstSeq, st.LastSeq+1 // answer in [lo, hi]; hi = "nothing retained qualifies"
	for lo < hi {
		mid := lo + (hi-lo)/2
		ss, ds, err := b.probe(ctx, mid)
		if err != nil {
			return 0, err
		}
		if ss == 0 { // nothing at or after mid
			hi = mid
			continue
		}
		if ds > afterSeq {
			hi = mid
		} else {
			lo = ss + 1
		}
	}
	return lo, nil
}

// probe returns the first retained message at stream seq >= seq: its stream
// seq and Diary seq; ss = 0 when there is none.
func (b *NATSBus) probe(ctx context.Context, seq uint64) (ss uint64, ds int64, err error) {
	m, err := b.str.GetMsg(ctx, seq, jetstream.WithGetMsgSubject(subjectAll))
	if errors.Is(err, jetstream.ErrMsgNotFound) {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, fmt.Errorf("events: get msg %d: %w", seq, err)
	}
	ds, err = strconv.ParseInt(m.Header.Get(headerSeq), 10, 64)
	if err != nil {
		var e Event
		if jerr := json.Unmarshal(m.Data, &e); jerr != nil {
			return 0, 0, fmt.Errorf("events: message %d has no seq", m.Sequence)
		}
		ds = e.Seq
	}
	return m.Sequence, ds, nil
}

// Close stops every subscription and the connection.
func (b *NATSBus) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	subs := make([]*natsSub, 0, len(b.stops))
	for s := range b.stops {
		subs = append(subs, s)
	}
	b.mu.Unlock()
	for _, s := range subs {
		s.cc.Stop()
	}
	return b.nc.Drain()
}
