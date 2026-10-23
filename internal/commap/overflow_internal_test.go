package commap

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"fortik/internal/alerts"
	"fortik/internal/config"
	"fortik/internal/diary"
	"fortik/internal/testutil"
)

// Phase 5 review (map #9): past the per-batch alert cap the remaining hidden
// signals are not dropped: executed ones are alerted first, and one overflow
// alert lists the rest.
func TestAlertCapRaisesOverflowAndPrefersExecuted(t *testing.T) {
	pool, _ := testutil.FortikDB(t)
	ctx := context.Background()
	d := diary.New(pool)
	al := alerts.NewPGStore(pool, d)
	w, err := NewWorker(pool, d, al, config.MapConfig{Window: 5 * time.Minute, RollupInterval: time.Second, Retention: 24 * time.Hour,
		EncodedParamMin: 256}, slog.New(slog.NewTextHandler(io.Discard, nil)), Options{Settle: -1})
	if err != nil {
		t.Fatal(err)
	}
	ws := time.Now().UTC().Truncate(5 * time.Minute)
	var aggs []*agg
	for i := 0; i < maxAlertsPerBatch+10; i++ {
		aggs = append(aggs, &agg{key: edgeKey{ws, "agent:noise", fmt.Sprintf("memory:kb/ns%03d", i), "REMEMBER"}, agentID: "noise",
			signals: map[string]*sigAgg{SignalLabelIntoMemory: {kind: SignalLabelIntoMemory}}})
	}
	// The real one comes last in the batch, but it ran.
	aggs = append(aggs, &agg{key: edgeKey{ws, "agent:exfil", "domain:evil.example", "READ"}, agentID: "exfil",
		signals: map[string]*sigAgg{SignalEncodedParam: {kind: SignalEncodedParam, executed: true}}})
	err = pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		n, hidden, err := w.raise(ctx, tx, aggs)
		if n != maxAlertsPerBatch || hidden != len(aggs) {
			t.Errorf("alerted %d hidden %d", n, hidden)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	var real, overflow int
	if err := pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE agent_id = 'exfil'),
		count(*) FILTER (WHERE dedup_key LIKE 'hidden_signal:overflow:%' AND details->>'not_alerted' = '11')
		FROM alerts WHERE kind = $1`, AlertKind).Scan(&real, &overflow); err != nil {
		t.Fatal(err)
	}
	if real != 1 || overflow != 1 {
		t.Fatalf("executed signal alerted %d, overflow alerts %d", real, overflow)
	}
}
