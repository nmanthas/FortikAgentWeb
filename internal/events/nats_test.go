package events

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const natsServerBin = "/opt/homebrew/bin/nats-server"

// startNATS launches a REAL nats-server with JetStream on a free port and a
// temp store dir, and kills it on cleanup.
func startNATS(t *testing.T) string {
	t.Helper()
	bin := natsServerBin
	if _, err := os.Stat(bin); err != nil {
		if p, lerr := exec.LookPath("nats-server"); lerr == nil {
			bin = p
		} else {
			t.Skipf("NATS JetStream test skipped: nats-server binary not found at %s or on PATH", natsServerBin)
		}
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	cmd := exec.Command(bin, "-js", "-a", "127.0.0.1", "-p", fmt.Sprint(port), "-sd", t.TempDir())
	if err := cmd.Start(); err != nil {
		t.Fatalf("start nats-server: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	url := fmt.Sprintf("nats://127.0.0.1:%d", port)
	deadline := time.Now().Add(10 * time.Second)
	for {
		nc, err := nats.Connect(url)
		if err == nil {
			nc.Close()
			return url
		}
		if time.Now().After(deadline) {
			t.Fatalf("nats-server did not come up: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestSubjectSanitising(t *testing.T) {
	for in, want := range map[string]string{
		"action.decided": "fortik.diary.action.decided",
		"a..b":           "fortik.diary.a._.b",
		"x.*.>":          "fortik.diary.x._._",
		"has space":      "fortik.diary.has_space",
		"":               "fortik.diary.unknown",
		"trail.":         "fortik.diary.trail._",
	} {
		if got := Subject(in); got != want {
			t.Errorf("Subject(%q) = %q want %q", in, got, want)
		}
	}
}

func TestNATSBusJetStream(t *testing.T) {
	url := startNATS(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	b, err := NewNATSBus(ctx, url, NATSOptions{Log: quietLog()})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	for i := int64(1); i <= 20; i++ {
		if err := b.Publish(ctx, ev(i)); err != nil {
			t.Fatal(err)
		}
	}
	// Re-publishing the same seqs (tailer retry / second replica) is deduped
	// by Nats-Msg-Id on the server.
	for i := int64(15); i <= 20; i++ {
		if err := b.Publish(ctx, ev(i)); err != nil {
			t.Fatal(err)
		}
	}
	info, err := b.str.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.State.Msgs != 20 {
		t.Fatalf("server-side dedupe failed: %d msgs", info.State.Msgs)
	}
	if info.Config.Name != StreamName || info.Config.Subjects[0] != "fortik.diary.>" {
		t.Fatalf("stream config: %+v", info.Config)
	}

	// Message lands on fortik.diary.<event_type>.
	m, err := b.str.GetMsg(ctx, 1)
	if err != nil || m.Subject != "fortik.diary.action.decided" || m.Header.Get(jetstream.MsgIDHeader) != "1" {
		t.Fatalf("subject/msg-id: %v %+v", err, m)
	}

	// Replay from the middle, then live.
	sctx, scancel := context.WithCancel(ctx)
	defer scancel()
	ch, err := b.Subscribe(sctx, 12)
	if err != nil {
		t.Fatal(err)
	}
	for want := int64(13); want <= 20; want++ {
		if got := recv(t, ch).Seq; got != want {
			t.Fatalf("replay: got %d want %d", got, want)
		}
	}
	if err := b.Publish(ctx, ev(21)); err != nil {
		t.Fatal(err)
	}
	if got := recv(t, ch).Seq; got != 21 {
		t.Fatalf("live: got %d", got)
	}

	// Subscribing past the end delivers only new events; from 0 replays all.
	live, _ := b.Subscribe(sctx, 21)
	all, _ := b.Subscribe(sctx, 0)
	if got := recv(t, all).Seq; got != 1 {
		t.Fatalf("full replay starts at %d", got)
	}
	_ = b.Publish(ctx, ev(22))
	if got := recv(t, live).Seq; got != 22 {
		t.Fatalf("live-only subscriber got %d", got)
	}

	// Cancel closes the channel.
	scancel()
	select {
	case <-drain(ch):
	case <-time.After(5 * time.Second):
		t.Fatal("subscription not closed after cancel")
	}
}

func drain(ch <-chan Event) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		for range ch {
		}
		close(done)
	}()
	return done
}
