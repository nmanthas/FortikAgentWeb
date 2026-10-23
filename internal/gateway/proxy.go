package gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
)

// hopByHop are connection-level headers never forwarded in either direction
// (RFC 9110 §7.6.1), plus the proxy-auth pair.
var hopByHop = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// DefaultForwardHeaders are the agent request headers forwarded upstream when
// a ProxyRequest names none. Everything else (Authorization, Cookie,
// X-Forwarded-*, X-Fortik-*, vendor headers) is dropped: the upstream sees
// only Fortik's credential and the minimum needed to serve the request.
var DefaultForwardHeaders = []string{"Accept", "Content-Type", "If-Match", "If-None-Match", "Range"}

// MaxCaptureBytes bounds a captured upstream response (ProxyRequest.Capture).
const MaxCaptureBytes = 4 << 20

// ProxyRequest describes one upstream call made on behalf of an agent.
type ProxyRequest struct {
	Client *http.Client // nil = http.DefaultClient
	Method string
	URL    string // full upstream URL including the (sanitised) query
	Body   []byte
	// Header is the incoming agent request header; only the ForwardHeaders
	// names are copied from it (DefaultForwardHeaders when nil).
	Header         http.Header
	ForwardHeaders []string
	// SetHeader is applied after copying (e.g. a rewritten Content-Type).
	SetHeader http.Header
	// Authorization is Fortik's credential (e.g. "Bearer ya29..."). It is
	// never taken from the agent request.
	Authorization string
	// Capture buffers the response body (up to MaxCaptureBytes) and returns
	// it in ProxyResult.Body as well as writing it to the client, for adapters
	// that must read the upstream answer (e.g. a created permission id).
	Capture bool
}

// ProxyResult reports what the upstream answered.
type ProxyResult struct {
	Status int
	Body   []byte // only with Capture
}

// ErrUpstream wraps transport failures talking to the upstream (no response).
var ErrUpstream = errors.New("upstream request failed")

// Proxy performs req and streams the upstream response to w with hop-by-hop
// headers, Set-Cookie and upstream X-Fortik-* headers removed. When it returns
// an error wrapping ErrUpstream nothing has been written to w.
func Proxy(ctx context.Context, w http.ResponseWriter, req ProxyRequest) (ProxyResult, error) {
	resp, err := Do(ctx, req)
	if err != nil {
		return ProxyResult{}, err
	}
	defer resp.Body.Close()
	var body io.Reader = resp.Body
	var captured []byte
	if req.Capture {
		b, err := io.ReadAll(io.LimitReader(resp.Body, MaxCaptureBytes+1))
		if err != nil {
			return ProxyResult{}, fmt.Errorf("%w: reading response: %v", ErrUpstream, err)
		}
		if len(b) > MaxCaptureBytes {
			return ProxyResult{}, fmt.Errorf("%w: response larger than %d bytes", ErrUpstream, MaxCaptureBytes)
		}
		captured = b
		body = bytes.NewReader(b)
	}
	CopyResponseHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(flushWriter{w}, body); err != nil {
		// Headers are already sent: the client sees a truncated body.
		return ProxyResult{Status: resp.StatusCode, Body: captured}, fmt.Errorf("streaming upstream response: %w", err)
	}
	return ProxyResult{Status: resp.StatusCode, Body: captured}, nil
}

// Do builds and sends the upstream request and returns the raw response (the
// caller closes the body). Transport errors wrap ErrUpstream.
func Do(ctx context.Context, req ProxyRequest) (*http.Response, error) {
	var body io.Reader
	if req.Body != nil {
		body = bytes.NewReader(req.Body)
	}
	out, err := http.NewRequestWithContext(ctx, req.Method, req.URL, body)
	if err != nil {
		return nil, fmt.Errorf("%w: building request: %v", ErrUpstream, err)
	}
	names := req.ForwardHeaders
	if names == nil {
		names = DefaultForwardHeaders
	}
	for _, n := range names {
		ck := textproto.CanonicalMIMEHeaderKey(n)
		if forbiddenForward(ck) {
			continue
		}
		for _, v := range req.Header.Values(ck) {
			out.Header.Add(ck, v)
		}
	}
	for k, vs := range req.SetHeader {
		out.Header.Del(k)
		for _, v := range vs {
			out.Header.Add(k, v)
		}
	}
	out.Header.Del("Authorization")
	if req.Authorization != "" {
		out.Header.Set("Authorization", req.Authorization)
	}
	client := req.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(out)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUpstream, scrubURLError(err))
	}
	return resp, nil
}

// forbiddenForward lists request headers that may never be copied from the
// agent, whatever an adapter's allowlist says.
func forbiddenForward(canonical string) bool {
	switch canonical {
	case "Authorization", "Cookie", "Host", "Content-Length", "Accept-Encoding", "Forwarded":
		return true
	}
	if strings.HasPrefix(canonical, "X-Fortik-") || strings.HasPrefix(canonical, "X-Forwarded-") {
		return true
	}
	for _, h := range hopByHop {
		if canonical == h {
			return true
		}
	}
	return false
}

// CopyResponseHeader copies upstream response headers to dst, dropping
// hop-by-hop headers (including any named in Connection), cookies and
// headers in Fortik's own namespace.
func CopyResponseHeader(dst, src http.Header) {
	drop := map[string]bool{"Set-Cookie": true, "Set-Cookie2": true}
	for _, h := range hopByHop {
		drop[h] = true
	}
	for _, v := range src.Values("Connection") {
		for _, f := range strings.Split(v, ",") {
			if f = strings.TrimSpace(f); f != "" {
				drop[textproto.CanonicalMIMEHeaderKey(f)] = true
			}
		}
	}
	for k, vs := range src {
		ck := textproto.CanonicalMIMEHeaderKey(k)
		if drop[ck] || strings.HasPrefix(ck, "X-Fortik-") {
			continue
		}
		for _, v := range vs {
			dst.Add(ck, v)
		}
	}
}

// scrubURLError drops the URL from transport errors (query strings may carry
// identifiers we do not want in logs) and keeps the cause.
func scrubURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		return ue.Err
	}
	return err
}

type flushWriter struct{ w http.ResponseWriter }

func (f flushWriter) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	if fl, ok := f.w.(http.Flusher); ok {
		fl.Flush()
	}
	return n, err
}
