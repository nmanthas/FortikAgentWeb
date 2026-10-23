// Command loadgen opens one MCP session (initialize + notifications/initialized)
// and then sends N sequential tools/call requests, reporting latency percentiles.
// Sequential (concurrency 1) on purpose: we want per-request overhead, not throughput.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

var (
	url      = flag.String("url", "http://127.0.0.1:8090/mcp", "MCP endpoint")
	n        = flag.Int("n", 1000, "measured tools/call requests")
	warmup   = flag.Int("warmup", 100, "unmeasured warmup requests")
	tool     = flag.String("tool", "echo", "tool name")
	agent    = flag.String("agent", "agent-green-1", "x-fortik-agent-id")
	instance = flag.String("instance", "inst-0001", "x-fortik-instance-id")
	label    = flag.String("label", "", "label for output")
	jsonOut  = flag.String("json", "", "append a JSON result line to this file")
)

var client = &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 4}, Timeout: 15 * time.Second}

func post(session string, body string) (*http.Response, []byte, error) {
	req, _ := http.NewRequest(http.MethodPost, *url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	req.Header.Set("x-fortik-agent-id", *agent)
	req.Header.Set("x-fortik-instance-id", *instance)
	if session != "" {
		req.Header.Set("Mcp-Session-Id", session)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp, b, err
}

// payload extracts the JSON-RPC message from a JSON or SSE response body.
func payload(b []byte) []byte {
	if bytes.HasPrefix(bytes.TrimSpace(b), []byte("{")) {
		return b
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		if l := sc.Text(); strings.HasPrefix(l, "data:") {
			return []byte(strings.TrimSpace(strings.TrimPrefix(l, "data:")))
		}
	}
	return b
}

func pct(d []time.Duration, p float64) time.Duration {
	idx := int(float64(len(d)-1) * p)
	return d[idx]
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func main() {
	flag.Parse()
	resp, b, err := post("", `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"fortik-loadgen","version":"0"}}}`)
	if err != nil || resp.StatusCode != 200 {
		fmt.Fprintf(os.Stderr, "initialize failed: %v %s\n", err, b)
		os.Exit(1)
	}
	session := resp.Header.Get("Mcp-Session-Id")
	if _, _, err := post(session, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); err != nil {
		fmt.Fprintln(os.Stderr, "initialized notification failed:", err)
		os.Exit(1)
	}
	lat := make([]time.Duration, 0, *n)
	errs := 0
	for i := 0; i < *warmup+*n; i++ {
		body := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":{"text":"hello %d"}}}`, i+1, *tool, i)
		t0 := time.Now()
		resp, b, err := post(session, body)
		el := time.Since(t0)
		ok := err == nil && resp.StatusCode == 200
		if ok {
			var m struct {
				Result json.RawMessage `json:"result"`
				Error  json.RawMessage `json:"error"`
			}
			if json.Unmarshal(payload(b), &m) != nil || m.Result == nil {
				ok = false
			}
		}
		if !ok {
			errs++
			if errs <= 3 {
				fmt.Fprintf(os.Stderr, "request %d failed: err=%v body=%s\n", i, err, b)
			}
		}
		if i >= *warmup {
			lat = append(lat, el)
		}
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	var sum time.Duration
	for _, d := range lat {
		sum += d
	}
	res := map[string]any{
		"label": *label, "url": *url, "n": len(lat), "errors": errs,
		"p50_ms": ms(pct(lat, 0.50)), "p95_ms": ms(pct(lat, 0.95)), "p99_ms": ms(pct(lat, 0.99)),
		"mean_ms": ms(sum / time.Duration(len(lat))), "max_ms": ms(lat[len(lat)-1]),
	}
	out, _ := json.Marshal(res)
	fmt.Println(string(out))
	if *jsonOut != "" {
		f, err := os.OpenFile(*jsonOut, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err == nil {
			fmt.Fprintln(f, string(out))
			f.Close()
		}
	}
	if errs > 0 {
		os.Exit(2)
	}
}
