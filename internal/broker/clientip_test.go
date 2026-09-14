package broker

import (
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func mustPrefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, len(cidrs))
	for i, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			t.Fatalf("bad cidr %q: %v", c, err)
		}
		out[i] = p
	}
	return out
}

func TestResolveClientIP_DirectConnectionIgnoresHeader(t *testing.T) {
	r := httptest.NewRequest("POST", "/auth/start", nil)
	r.RemoteAddr = "203.0.113.9:5555"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")

	assert.Equal(t, "203.0.113.9", resolveClientIP(r, nil))
}

func TestResolveClientIP_TrustedProxyUsesForwardedFor(t *testing.T) {
	r := httptest.NewRequest("POST", "/auth/start", nil)
	r.RemoteAddr = "10.0.0.5:5555"
	r.Header.Set("X-Forwarded-For", "203.0.113.9")

	trusted := mustPrefixes(t, "10.0.0.0/8")
	assert.Equal(t, "203.0.113.9", resolveClientIP(r, trusted))
}

func TestResolveClientIP_UntrustedProxySpoofIsIgnored(t *testing.T) {
	r := httptest.NewRequest("POST", "/auth/start", nil)
	r.RemoteAddr = "198.51.100.7:5555" // not in the trusted list
	r.Header.Set("X-Forwarded-For", "1.2.3.4")

	trusted := mustPrefixes(t, "10.0.0.0/8")
	assert.Equal(t, "198.51.100.7", resolveClientIP(r, trusted), "an untrusted peer's header must never be believed")
}

func TestResolveClientIP_MultiHopStopsAtFirstUntrusted(t *testing.T) {
	r := httptest.NewRequest("POST", "/auth/start", nil)
	r.RemoteAddr = "10.0.0.5:5555"
	r.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.4")

	trusted := mustPrefixes(t, "10.0.0.0/8")
	assert.Equal(t, "203.0.113.9", resolveClientIP(r, trusted))
}

func TestResolveClientIP_AllHopsTrustedFallsBackToPeer(t *testing.T) {
	r := httptest.NewRequest("POST", "/auth/start", nil)
	r.RemoteAddr = "10.0.0.5:5555"
	r.Header.Set("X-Forwarded-For", "10.0.0.3, 10.0.0.4")

	trusted := mustPrefixes(t, "10.0.0.0/8")
	assert.Equal(t, "10.0.0.5", resolveClientIP(r, trusted))
}

func TestIsAllowedClient_EmptyAllowedMeansNoGating(t *testing.T) {
	assert.True(t, isAllowedClient("203.0.113.9", nil))
}

func TestIsAllowedClient_RejectsOutsideCIDR(t *testing.T) {
	allowed := mustPrefixes(t, "192.168.0.0/16")
	assert.False(t, isAllowedClient("203.0.113.9", allowed))
	assert.True(t, isAllowedClient("192.168.1.5", allowed))
}
