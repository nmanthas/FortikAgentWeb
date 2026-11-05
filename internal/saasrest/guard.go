package saasrest

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"syscall"
	"time"
)

// Guard decides which upstream URLs Fortik may send a provider's
// credentials to (an SSRF guard: an administrator-entered URL cannot reach
// another host or an internal address).
//
// A URL is permitted when it is https and its host is one of the provider's
// own domains (suffixes), or is listed in config saas_upstreams.allowed_hosts.
// Loopback http(s) is permitted only with saas_upstreams.allow_loopback
// (local fakes). Every dialled address is checked again at connect time
// (DNS rebinding): private, link-local, multicast and unspecified addresses
// are refused, and loopback unless allowed.
type Guard struct {
	AllowedHosts  []string
	AllowLoopback bool
}

// providerSuffixes are each provider's own API domains.
var providerSuffixes = map[string][]string{
	"salesforce": {".salesforce.com"},
	"servicenow": {".service-now.com", ".servicenowservices.com"},
	"sap":        {".s4hana.cloud.sap", ".s4hana.ondemand.com"},
}

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// Refused returns why rawURL may not receive provider's credentials ("" if
// permitted).
func (g Guard) Refused(provider, rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || u.User != nil {
		return "not a valid absolute URL"
	}
	host := strings.ToLower(u.Hostname())
	if isLoopbackHost(host) {
		if !g.AllowLoopback {
			return "loopback endpoints are allowed only with saas_upstreams.allow_loopback (local fakes in development)"
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return "the URL must use https"
		}
		return ""
	}
	if u.Scheme != "https" {
		return "the URL must use https"
	}
	if slices.Contains(g.AllowedHosts, host) {
		return ""
	}
	for _, suf := range providerSuffixes[provider] {
		if strings.HasSuffix(host, suf) {
			return ""
		}
	}
	return fmt.Sprintf("host %q is not a %s domain (%s) and is not in saas_upstreams.allowed_hosts", clip(host, 100), provider,
		strings.Join(providerSuffixes[provider], ", "))
}

var errAddressRefused = errors.New("address refused")

func (g Guard) addressRefused(ip net.IP) string {
	switch {
	case ip == nil:
		return "unparseable address"
	case ip.IsLoopback():
		if g.AllowLoopback {
			return ""
		}
		return "loopback"
	case ip.IsPrivate(), ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(), ip.IsMulticast(), ip.IsUnspecified(), ip.IsInterfaceLocalMulticast():
		return "not a public address"
	}
	// 100.64.0.0/10 (carrier-grade NAT) is not public either.
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 64 {
		return "not a public address"
	}
	return ""
}

// Client is an HTTP client that dials only permitted addresses, never uses
// a proxy and never follows redirects (a redirect could carry credentials
// to another host).
func (g Guard) Client(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			if r := g.addressRefused(net.ParseIP(host)); r != "" {
				return fmt.Errorf("%w: %s (%s)", errAddressRefused, host, r)
			}
			return nil
		},
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: timeout,
			MaxIdleConnsPerHost:   4,
			IdleConnTimeout:       60 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// refusedErr reports a dial refused by the guard.
func refusedErr(err error) bool { return errors.Is(err, errAddressRefused) }

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ctxWith bounds one upstream call.
func ctxWith(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, d)
}
