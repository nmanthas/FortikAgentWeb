package policy

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"sync"
)

// CaptureEnv names a file to which every evaluated Input is appended as one
// JSON line (development only: it builds the replay corpus from real test
// and demo traffic, internal/replay). Unset in production. The inputs carry
// action metadata (targets, labels, sizes), never secrets or payloads.
const CaptureEnv = "FORTIK_POLICY_CAPTURE"

var capture struct {
	once sync.Once
	mu   sync.Mutex
	f    *os.File
}

func captureInput(in Input) {
	capture.once.Do(func() {
		if p := os.Getenv(CaptureEnv); p != "" {
			// "{pid}" in the path gives each process its own file (parallel test binaries).
			p = strings.ReplaceAll(p, "{pid}", strconv.Itoa(os.Getpid()))
			capture.f, _ = os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		}
	})
	if capture.f == nil {
		return
	}
	b, err := json.Marshal(in)
	if err != nil {
		return
	}
	capture.mu.Lock()
	_, _ = capture.f.Write(append(b, '\n'))
	capture.mu.Unlock()
}

// Capturing reports whether input capture is on (logged at startup).
func Capturing() bool { return os.Getenv(CaptureEnv) != "" }
