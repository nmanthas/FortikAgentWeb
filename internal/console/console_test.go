package console

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

const indexHTML = `<!doctype html><html><head><title>Fortik</title></head><body><div id="root"></div></body></html>`

func testFS() fstest.MapFS {
	return fstest.MapFS{
		"index.html":            {Data: []byte(indexHTML)},
		"favicon.svg":           {Data: []byte(`<svg xmlns="http://www.w3.org/2000/svg"></svg>`)},
		"assets/index-abc1.js":  {Data: []byte(`console.log("fortik")`)},
		"assets/index-abc1.css": {Data: []byte(`body{}`)},
	}
}

func get(t *testing.T, h http.Handler, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func assertSecurityHeaders(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	want := map[string]string{
		"Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "no-referrer",
	}
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
}

func TestSPAFallbackServesIndexForClientRoutes(t *testing.T) {
	h := New(testFS())
	for _, p := range []string{"/", "/index.html", "/agents", "/agents/agent-1", "/integrations", "/agents/a/b/c"} {
		rec := get(t, h, http.MethodGet, p)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s: status %d", p, rec.Code)
		}
		if rec.Body.String() != indexHTML {
			t.Fatalf("GET %s: body is not index.html: %q", p, rec.Body.String())
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("GET %s: Content-Type %q", p, ct)
		}
		if cc := rec.Header().Get("Cache-Control"); cc != "no-cache" {
			t.Errorf("GET %s: Cache-Control %q, want no-cache", p, cc)
		}
		assertSecurityHeaders(t, rec)
	}
}

func TestAssetsAreServedWithLongCache(t *testing.T) {
	h := New(testFS())
	rec := get(t, h, http.MethodGet, "/assets/index-abc1.js")
	if rec.Code != http.StatusOK || rec.Body.String() != `console.log("fortik")` {
		t.Fatalf("asset: %d %q", rec.Code, rec.Body.String())
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=31536000, immutable" {
		t.Errorf("asset Cache-Control %q", cc)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Errorf("asset Content-Type %q", ct)
	}
	assertSecurityHeaders(t, rec)

	// Unhashed root files must be revalidated.
	rec = get(t, h, http.MethodGet, "/favicon.svg")
	if rec.Code != http.StatusOK {
		t.Fatalf("favicon: %d", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("favicon Cache-Control %q", cc)
	}
}

func TestMissingFileWithExtensionIs404NotIndex(t *testing.T) {
	h := New(testFS())
	for _, p := range []string{"/assets/gone-123.js", "/favicon.ico", "/robots.txt"} {
		rec := get(t, h, http.MethodGet, p)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("GET %s: status %d, want 404", p, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "<html") {
			t.Fatalf("GET %s: served HTML for a missing asset", p)
		}
		assertSecurityHeaders(t, rec)
	}
}

func TestReservedPathsAreNotShadowed(t *testing.T) {
	h := New(testFS())
	for _, p := range []string{"/v1", "/v1/", "/v1/agents", "/v1/unknown/route", "/auth", "/auth/whatever", "/gw/google/gmail/v1/x", "/gw"} {
		for _, m := range []string{http.MethodGet, http.MethodPost} {
			rec := get(t, h, m, p)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("%s %s: status %d, want 404", m, p, rec.Code)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
				t.Fatalf("%s %s: Content-Type %q, want JSON", m, p, ct)
			}
			var body map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["error"] == "" {
				t.Fatalf("%s %s: body %q is not an error object", m, p, rec.Body.String())
			}
			assertSecurityHeaders(t, rec)
		}
	}
	// Prefix matching is by path segment: these are client routes.
	for _, p := range []string{"/v1x", "/authors", "/gwen"} {
		if rec := get(t, h, http.MethodGet, p); rec.Code != http.StatusOK || rec.Body.String() != indexHTML {
			t.Fatalf("GET %s: %d, want the SPA", p, rec.Code)
		}
	}
}

func TestNonGetMethodsRefused(t *testing.T) {
	h := New(testFS())
	rec := get(t, h, http.MethodPost, "/agents")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /agents: %d", rec.Code)
	}
	if rec.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("Allow %q", rec.Header().Get("Allow"))
	}
	if rec := get(t, h, http.MethodHead, "/agents"); rec.Code != http.StatusOK {
		t.Fatalf("HEAD /agents: %d", rec.Code)
	}
}

func TestPathTraversalStaysInsideFS(t *testing.T) {
	h := New(testFS())
	rec := get(t, h, http.MethodGet, "/assets/../../etc/passwd")
	if rec.Code == http.StatusOK && rec.Body.String() != indexHTML {
		t.Fatalf("traversal served unexpected content: %q", rec.Body.String())
	}
}

func TestMissingBuildIsReported(t *testing.T) {
	h := New(fstest.MapFS{})
	rec := get(t, h, http.MethodGet, "/agents")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", rec.Code)
	}
}

func TestEmbeddedBuildHasIndex(t *testing.T) {
	sub, err := fs.Sub(embedded, "dist")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Stat(sub, "index.html"); err != nil {
		t.Fatalf("embedded dist has no index.html: %v", err)
	}
	rec := get(t, Handler(), http.MethodGet, "/agents")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<html") {
		t.Fatalf("embedded handler: %d", rec.Code)
	}
	assertSecurityHeaders(t, rec)
}
