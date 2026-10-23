package hook

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// HostPort is one network endpoint (a database server or the Fortik proxy).
type HostPort struct {
	Host string // canonical: lower case, no brackets, loopback names folded to 127.0.0.1
	Port int
}

func (hp HostPort) String() string {
	if strings.HasPrefix(hp.Host, "socket:") {
		return hp.Host
	}
	return net.JoinHostPort(hp.Host, strconv.Itoa(hp.Port))
}

// ParseProxyHosts parses config.HookConfig.ProxyHosts. Every entry must name
// a host AND a port: the Fortik proxy and the database it fronts often share
// a host (127.0.0.1:6432 vs 127.0.0.1:5432), so a host-only entry would
// excuse exactly the bypass POL-501 exists to catch.
func ParseProxyHosts(entries []string) ([]HostPort, error) {
	out := make([]HostPort, 0, len(entries))
	for _, e := range entries {
		h, p, err := net.SplitHostPort(strings.TrimSpace(e))
		if err != nil {
			return nil, fmt.Errorf("hook: proxy_hosts entry %q must be host:port: %v", e, err)
		}
		port, err := strconv.Atoi(p)
		if err != nil || port <= 0 || port > 65535 || h == "" {
			return nil, fmt.Errorf("hook: proxy_hosts entry %q must be host:port with a valid port", e)
		}
		out = append(out, HostPort{Host: canonHost(h), Port: port})
	}
	return out, nil
}

// canonHost lower-cases a host name, strips brackets and a trailing dot, and
// folds the loopback spellings together so "localhost:6432" matches a proxy
// configured as "127.0.0.1:6432".
func canonHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	h = strings.TrimSuffix(h, ".")
	switch h {
	case "localhost", "ip6-localhost", "ip6-loopback", "::1", "0:0:0:0:0:0:0:1":
		return "127.0.0.1"
	}
	return h
}

func isProxy(hp HostPort, proxies []HostPort) bool {
	for _, p := range proxies {
		if p.Host == hp.Host && p.Port == hp.Port {
			return true
		}
	}
	return false
}

// isExternal reports whether host is outside the company: not loopback,
// private, link-local, single-label or a reserved internal suffix, and not
// matched by the configured internal hosts ("example.corp", "*.example.corp"
// or ".example.corp").
func isExternal(host string, internal []string) bool {
	h := canonHost(host)
	if h == "" {
		return false
	}
	if ip, err := netip.ParseAddr(h); err == nil {
		return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified())
	}
	if !strings.Contains(h, ".") {
		return false // single-label names resolve inside the network
	}
	for _, suf := range []string{".localhost", ".local", ".internal", ".lan", ".home.arpa", ".intranet"} {
		if strings.HasSuffix(h, suf) {
			return false
		}
	}
	for _, pat := range internal {
		pat = strings.ToLower(strings.TrimSpace(pat))
		switch {
		case pat == "":
		case strings.HasPrefix(pat, "*."):
			if strings.HasSuffix(h, pat[1:]) {
				return false
			}
		case strings.HasPrefix(pat, "."):
			if strings.HasSuffix(h, pat) || h == pat[1:] {
				return false
			}
		case h == pat:
			return false
		}
	}
	return true
}

// urlHost extracts the host of a URL-ish argument (curl and friends accept
// "example.com/x" without a scheme). ok is false when no host can be found.
func urlHost(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", false
	}
	if strings.HasPrefix(s, ":") { // httpie shorthand ":8080/path" = localhost
		return "127.0.0.1", true
	}
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	if u, err := url.Parse(s); err == nil && u.Hostname() != "" {
		return canonHost(u.Hostname()), true
	}
	// Fall back to the authority by hand (curl globs like {a,b} break url.Parse).
	rest := s[strings.Index(s, "://")+3:]
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		rest = rest[i+1:]
	}
	if h, _, err := net.SplitHostPort(rest); err == nil {
		rest = h
	}
	rest = canonHost(rest)
	return rest, rest != ""
}

// remoteSpec parses an scp/rsync operand: "[user@]host:path", "host::module"
// or "rsync://host/..."/"scp://host/...". Local paths ("/x", "./a:b", "C:")
// are not remote.
func remoteSpec(s string) (host string, ok bool) {
	for _, scheme := range []string{"rsync://", "scp://", "sftp://", "ssh://"} {
		if strings.HasPrefix(strings.ToLower(s), scheme) {
			return urlHost(s)
		}
	}
	if s == "" || strings.HasPrefix(s, "/") || strings.HasPrefix(s, ".") || strings.HasPrefix(s, "~") {
		return "", false
	}
	colon := strings.Index(s, ":")
	if colon <= 0 {
		return "", false
	}
	if slash := strings.Index(s, "/"); slash >= 0 && slash < colon {
		return "", false
	}
	h := s[:colon]
	if strings.HasPrefix(h, "[") { // [ipv6]:path
		if end := strings.Index(s, "]"); end > 0 {
			h = s[1:end]
		}
	}
	if i := strings.LastIndex(h, "@"); i >= 0 {
		h = h[i+1:]
	}
	h = canonHost(h)
	return h, h != ""
}

// sshDestination parses ssh's destination: "[user@]host" or
// "ssh://[user@]host[:port]".
func sshDestination(s string) (string, bool) {
	if strings.HasPrefix(strings.ToLower(s), "ssh://") {
		return urlHost(s)
	}
	h := s
	if i := strings.LastIndex(h, "@"); i >= 0 {
		h = h[i+1:]
	}
	h = canonHost(h)
	return h, h != "" && !strings.ContainsAny(h, "/ ")
}
