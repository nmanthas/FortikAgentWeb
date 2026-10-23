package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHostAllowlist(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
	h := HostAllowlist(true, []string{"console.acme.com"}, ok)
	for host, want := range map[string]int{
		"127.0.0.1:8080": 204, "localhost:8080": 204, "[::1]:8080": 204, "console.acme.com": 204,
		"rebind.attacker.example:8080": 421, "127.0.0.1.nip.io:8080": 421, "": 421,
	} {
		r := httptest.NewRequest("GET", "/v1/agents", nil)
		r.Host = host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Errorf("host %q: got %d want %d", host, w.Code, want)
		}
	}
}
