package broker

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// resolveClientIP trusts X-Forwarded-For only when the immediate peer, and
// each hop walked past, is in trusted; it never trusts an untrusted header.
func resolveClientIP(r *http.Request, trusted []netip.Prefix) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if !isTrustedHost(host, trusted) {
		return host
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return host
	}
	hops := strings.Split(xff, ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(hops[i])
		if !isTrustedHost(hop, trusted) {
			return hop
		}
	}
	return host
}

func isTrustedHost(host string, trusted []netip.Prefix) bool {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// isAllowedClient reports whether ip is inside one of allowed (empty allowed = no gating).
func isAllowedClient(ip string, allowed []netip.Prefix) bool {
	if len(allowed) == 0 {
		return true
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, p := range allowed {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
