package memory

import (
	"context"
	"log/slog"
	"time"
)

// PromotionWorker promotes due, unflagged staged items every
// config.MemoryConfig.PromotionPoll, except items written by agents whose
// memory access is staging_only or none.
type PromotionWorker struct {
	svc  *Service
	poll time.Duration
	log  *slog.Logger
}

// NewPromotionWorker builds the worker (poll <= 0 means 30s).
func NewPromotionWorker(svc *Service, poll time.Duration, log *slog.Logger) *PromotionWorker {
	if poll <= 0 {
		poll = 30 * time.Second
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &PromotionWorker{svc: svc, poll: poll, log: log}
}

// Run promotes every poll interval until ctx ends.
func (w *PromotionWorker) Run(ctx context.Context) {
	t := time.NewTicker(w.poll)
	defer t.Stop()
	for {
		res, err := w.svc.PromoteDue(ctx)
		switch {
		case err != nil && ctx.Err() == nil:
			w.log.Error("memory promotion pass failed", "promoted", res.Promoted, "err", err)
		case res.Promoted > 0:
			w.log.Info("memory items promoted", "promoted", res.Promoted, "held_agents", res.HeldAgents)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// SnapshotWorker takes automatic snapshots every config.MemoryConfig.SnapshotEvery
// of each namespace whose contents changed since its newest snapshot. A
// snapshot is recorded clean when no item in the namespace is flagged.
type SnapshotWorker struct {
	svc   *Service
	every time.Duration
	poll  time.Duration
	log   *slog.Logger
}

// NewSnapshotWorker builds the worker. every <= 0 disables automatic
// snapshots (Run returns at once; manual snapshots still work).
func NewSnapshotWorker(svc *Service, every time.Duration, log *slog.Logger) *SnapshotWorker {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	// Check a few times per period so a namespace is never more than about
	// every + every/4 behind (and at least once a minute for long periods).
	poll := every / 4
	if poll > time.Minute {
		poll = time.Minute
	}
	if poll < 100*time.Millisecond {
		poll = 100 * time.Millisecond
	}
	return &SnapshotWorker{svc: svc, every: every, poll: poll, log: log}
}

// Run takes due snapshots until ctx ends.
func (w *SnapshotWorker) Run(ctx context.Context) {
	if w.every <= 0 {
		w.log.Info("automatic memory snapshots disabled (memory.snapshot_every = 0)")
		return
	}
	t := time.NewTicker(w.poll)
	defer t.Stop()
	for {
		n, err := w.svc.AutoSnapshot(ctx, w.every)
		switch {
		case err != nil && ctx.Err() == nil:
			w.log.Error("automatic memory snapshot pass failed", "taken", n, "err", err)
		case n > 0:
			w.log.Info("automatic memory snapshots taken", "count", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
