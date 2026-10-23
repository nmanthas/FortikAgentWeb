package api_test

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/api"
	"fortik/internal/diary"
	"fortik/internal/events"
)

// Regression: the SSE stream must flush through the API's middleware stack
// (the logging ResponseWriter wrapper used to swallow Flush, so the console
// never received live events).
func TestEventStreamFlushesThroughAPIStack(t *testing.T) {
	var d *diary.Diary
	e := setupWith(t, fakeExec{}, setupOpts{
		configure: func(_ *api.Server, _ *pgxpool.Pool, dd *diary.Diary) { d = dd },
		mount: func(s *api.Server) {
			bus := events.NewMemoryBus(100)
			tailer := events.NewTailer(d, bus, slog.New(slog.NewTextHandler(io.Discard, nil)))
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			go tailer.Run(ctx)
			s.Mount(events.NewSSE(bus, events.SSEOptions{Head: tailer.Head, Backfill: tailer.Backfill, Heartbeat: time.Second}).Mount)
		},
	})
	if _, err := e.diary.Append(context.Background(), diary.Event{EventType: "test.event", Actor: "test"}); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", e.srv.URL+"/v1/events/stream", nil)
	req.Header.Set("Authorization", "Bearer "+tokAuditor)
	req.Header.Set("Last-Event-ID", "0")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "event: diary") {
			return // received a flushed event
		}
	}
	t.Fatal("no diary event received through the API stack")
}
