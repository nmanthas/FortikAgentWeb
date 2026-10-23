package httpx

import (
	"net"
	"net/http"
	"strings"
)

// HostName returns the lower-cased host part of a Host header or URL host
// ("127.0.0.1:8080" -> "127.0.0.1", "[::1]:80" -> "::1").
func HostName(hostport string) string {
	h := hostport
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		h = host
	}
	return strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(h, "["), "]"))
}

// IsLoopbackName reports whether host (with or without port) names the
// loopback interface literally: "localhost" or a loopback IP. A DNS name
// that merely resolves to 127.0.0.1 (DNS rebinding) is not loopback.
func IsLoopbackName(hostport string) bool {
	h := HostName(hostport)
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// HostAllowlist refuses requests whose Host header is not allowed (DNS
// rebinding defence for cookie-authenticated browser surfaces). When
// loopback is true, literal loopback names are allowed; extra lists further
// allowed host names (port-insensitive). With loopback false and no extra
// hosts, every Host is accepted.
func HostAllowlist(loopback bool, extra []string, next http.Handler) http.Handler {
	allowed := map[string]bool{}
	for _, h := range extra {
		if h = HostName(strings.TrimSpace(h)); h != "" {
			allowed[h] = true
		}
	}
	if !loopback && len(allowed) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (loopback && IsLoopbackName(r.Host)) || allowed[HostName(r.Host)] {
			next.ServeHTTP(w, r)
			return
		}
		WriteError(w, http.StatusMisdirectedRequest, "host not allowed")
	})
}
