package broker

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/rupivbluegreen/xdauth/internal/store"
)

func newTestBroker(t *testing.T, cfg Config) *Broker {
	t.Helper()
	st := store.NewMemory(time.Minute)
	t.Cleanup(st.Close)
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	cfg.BaseURL = "http://broker.example"
	return New(cfg, st, fakeNoopIdP{})
}

func startReq(t *testing.T, remoteAddr, xff, hint string) *http.Request {
	t.Helper()
	body := `{"login_hint":"` + hint + `","code_challenge":"c","code_challenge_method":"S256"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/start", strings.NewReader(body))
	req.RemoteAddr = remoteAddr
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	return req
}

// TestRateLimit_SeparatesClientsBehindTrustedProxy: WS5 regression test.
// Without trusted-proxy IP resolution, two distinct clients behind one
// reverse proxy would collapse into a single rate-limit bucket.
func TestRateLimit_SeparatesClientsBehindTrustedProxy(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	b := newTestBroker(t, Config{TrustedProxies: trusted, StartRateBurst: 1})

	r1 := startReq(t, "10.0.0.5:1", "203.0.113.1", "alice")
	rec1 := httptest.NewRecorder()
	b.Router().ServeHTTP(rec1, r1)
	require.Equal(t, http.StatusOK, rec1.Code)

	// same client retries immediately: burst exhausted, rate-limited.
	r1b := startReq(t, "10.0.0.5:1", "203.0.113.1", "alice2")
	rec1b := httptest.NewRecorder()
	b.Router().ServeHTTP(rec1b, r1b)
	require.Equal(t, http.StatusTooManyRequests, rec1b.Code)

	// a different real client, same proxy, must not be limited by client 1.
	r2 := startReq(t, "10.0.0.5:1", "203.0.113.2", "bob")
	rec2 := httptest.NewRecorder()
	b.Router().ServeHTTP(rec2, r2)
	require.Equal(t, http.StatusOK, rec2.Code)
}

func TestHandleStart_AllowedCIDRRejectsOutsideNetwork(t *testing.T) {
	allowed := []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}
	b := newTestBroker(t, Config{AllowedClientCIDRs: allowed})

	r := startReq(t, "203.0.113.9:1", "", "alice")
	rec := httptest.NewRecorder()
	b.Router().ServeHTTP(rec, r)
	require.Equal(t, http.StatusForbidden, rec.Code)
}

func TestHandleStart_AllowedCIDRAcceptsInsideNetwork(t *testing.T) {
	allowed := []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}
	b := newTestBroker(t, Config{AllowedClientCIDRs: allowed})

	r := startReq(t, "192.168.1.5:1", "", "alice")
	rec := httptest.NewRecorder()
	b.Router().ServeHTTP(rec, r)
	require.Equal(t, http.StatusOK, rec.Code)
}
