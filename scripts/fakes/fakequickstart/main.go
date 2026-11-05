// Command fakequickstart serves a LOCAL FAKE MCP server shaped like the
// NetSuite QuickStart MCP server (internal/mcpclient/mcpfake) for
// scripts/demo-netsuite-quickstart.sh. It is NOT NetSuite: tool names follow
// Oracle's documented list, descriptions and schemas are invented.
//
// It generates a random personal access token, writes it to -token-out
// (0600) for the demo to configure, and exposes /fake/control and
// /fake/calls on the same port for the demo to change behaviour and read
// what it received (never the token).
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"fortik/internal/mcpclient/mcpfake"
)

func main() {
	port := flag.Int("port", 18410, "listen port (127.0.0.1)")
	tokenOut := flag.String("token-out", "", "write the generated tokens here, one per line: read-only, read-write (0600)")
	flag.Parse()
	gen := func() string {
		b := make([]byte, 24)
		_, _ = rand.Read(b)
		return "fakeqs-" + hex.EncodeToString(b)
	}
	roTok, rwTok := gen(), gen()
	if *tokenOut != "" {
		if err := os.WriteFile(*tokenOut, []byte(roTok+"\n"+rwTok+"\n"), 0o600); err != nil {
			log.Fatal(err)
		}
	}
	var mu sync.Mutex // serialises requests: control changes the fake's fields
	fake := &mcpfake.Server{Token: roTok, SSE: true, PageSize: 10,
		Records: map[string]map[string]map[string]any{"Customer": {"12": {"email": "ap@acme.example", "memo": "LOCAL FAKE record"}}}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /fake/control", func(w http.ResponseWriter, r *http.Request) {
		var c struct {
			Token        string `json:"token"` // "ro" | "rw"
			ExpiredToken bool   `json:"expired_token"`
			InitStatus   int    `json:"init_status"`
		}
		if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch c.Token {
		case "rw":
			fake.Token, fake.ReadWrite = rwTok, true
		case "ro", "":
			fake.Token, fake.ReadWrite = roTok, false
		}
		fake.ExpiredToken, fake.InitStatus = c.ExpiredToken, c.InitStatus
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /fake/calls", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		auth := map[string]int{}
		for _, h := range fake.AuthHeaders() {
			switch {
			case h == "Bearer "+roTok:
				auth["read_only_token"]++
			case h == "Bearer "+rwTok:
				auth["read_write_token"]++
			case strings.HasPrefix(h, "Bearer "):
				auth["other_bearer"]++
			default:
				auth["none"]++
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"calls": fake.Calls(), "authorization": auth})
	})
	mux.HandleFunc("GET /fake/record", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(fake.Record(r.URL.Query().Get("type"), r.URL.Query().Get("id")))
	})
	mux.HandleFunc("GET /fake/toolcalls", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		n := map[string]int{}
		for _, c := range fake.ToolCalls() {
			n[c.Name]++
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(n)
	})
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		fake.ServeHTTP(w, r)
	})
	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	log.Printf("LOCAL FAKE QuickStart MCP server (not NetSuite) on http://%s/mcp", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
