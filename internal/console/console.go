// Package console serves the Fortik web console: the Vite build of
// web/console, embedded into the binary from internal/console/dist.
//
// The handler is a single-page-app file server:
//
//   - existing files are served as-is; hashed bundles under /assets/ get a
//     one-year immutable cache, everything else (index.html included) must
//     be revalidated;
//   - any other GET path without a file extension falls back to index.html so
//     client-side routes (/agents/x, /integrations) survive a reload;
//   - API, auth and gateway paths (/v1, /auth, /gw) are never answered with
//     the SPA: if one reaches this handler, no route matched and the answer is
//     a JSON 404, so API clients never mistake HTML for data;
//   - every response carries a strict Content-Security-Policy and the other
//     security headers below.
//
// Build the real bundle with `npm run build` in web/console. A placeholder
// dist/index.html is kept in the repository so `go build` works without npm.
package console

import (
	"bytes"
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"

	"fortik/internal/httpx"
)

//go:embed all:dist
var embedded embed.FS

// ContentSecurityPolicy is sent with every console response. The bundle has
// no inline scripts; inline styles are allowed for React style attributes.
const ContentSecurityPolicy = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; " +
	"connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"

// Cache-Control values.
const (
	cacheImmutable  = "public, max-age=31536000, immutable"
	cacheRevalidate = "no-cache"
)

// reservedPrefixes are server routes the SPA must never shadow.
var reservedPrefixes = []string{"/v1", "/auth", "/gw"}

// Handler serves the embedded console build.
func Handler() http.Handler {
	sub, err := fs.Sub(embedded, "dist")
	if err != nil {
		// Only possible if the embed directive changes; fail loudly at startup.
		panic("console: embedded dist missing: " + err.Error())
	}
	return New(sub)
}

// New serves the console from fsys (the root of a Vite build: index.html and
// assets/). Exposed for tests.
func New(fsys fs.FS) http.Handler {
	return &spa{fsys: fsys}
}

type spa struct {
	fsys fs.FS
}

func (h *spa) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w.Header())

	p := r.URL.Path
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	clean := path.Clean(p)
	if isReserved(p) || isReserved(clean) {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		httpx.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	name := strings.TrimPrefix(clean, "/")
	if name != "" && name != "index.html" {
		if data, modTime, ok := h.readFile(name); ok {
			cache := cacheRevalidate
			if strings.HasPrefix(clean, "/assets/") {
				cache = cacheImmutable
			}
			w.Header().Set("Cache-Control", cache)
			http.ServeContent(w, r, path.Base(name), modTime, bytes.NewReader(data))
			return
		}
		// A missing file with an extension (a stale /assets/x.js, /favicon.ico)
		// is a real 404: answering it with HTML would break the browser's
		// MIME checks and hide the error.
		if path.Ext(clean) != "" {
			w.Header().Set("Cache-Control", cacheRevalidate)
			http.Error(w, "404 page not found", http.StatusNotFound)
			return
		}
	}
	h.serveIndex(w, r)
}

func (h *spa) serveIndex(w http.ResponseWriter, r *http.Request) {
	data, modTime, ok := h.readFile("index.html")
	if !ok {
		httpx.WriteError(w, http.StatusServiceUnavailable, "console not built (run npm run build in web/console)")
		return
	}
	w.Header().Set("Cache-Control", cacheRevalidate)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	http.ServeContent(w, r, "index.html", modTime, bytes.NewReader(data))
}

// readFile returns a regular file's contents; directories and errors are
// "not found".
func (h *spa) readFile(name string) ([]byte, time.Time, bool) {
	if !fs.ValidPath(name) {
		return nil, time.Time{}, false
	}
	st, err := fs.Stat(h.fsys, name)
	if err != nil || !st.Mode().IsRegular() {
		return nil, time.Time{}, false
	}
	data, err := fs.ReadFile(h.fsys, name)
	if err != nil {
		return nil, time.Time{}, false
	}
	return data, st.ModTime(), true
}

func isReserved(p string) bool {
	for _, pre := range reservedPrefixes {
		if p == pre || strings.HasPrefix(p, pre+"/") {
			return true
		}
	}
	return false
}

func setSecurityHeaders(h http.Header) {
	h.Set("Content-Security-Policy", ContentSecurityPolicy)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
}
