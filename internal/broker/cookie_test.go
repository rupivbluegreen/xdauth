package broker

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSetSessionCookie_HTTPS is the SAML ACS case: SameSite must be None (Lax never rides along on the cross-site POST) and Secure must be true, since browsers require Secure alongside SameSite=None.
func TestSetSessionCookie_HTTPS(t *testing.T) {
	r := httptest.NewRequest("GET", "https://broker.example/auth/verify/abc", nil)
	r.TLS = &tls.ConnectionState{}
	w := httptest.NewRecorder()

	setSessionCookie(w, r, "sess-123")

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	require.Equal(t, "sess-123", cookies[0].Value)
	require.True(t, cookies[0].Secure)
	require.Equal(t, http.SameSiteNoneMode, cookies[0].SameSite)
}

// TestSetSessionCookie_PlainHTTP is the local-dev fallback: SameSite=None without Secure is dropped by browsers, so it must stay Lax.
func TestSetSessionCookie_PlainHTTP(t *testing.T) {
	r := httptest.NewRequest("GET", "http://localhost:8080/auth/verify/abc", nil)
	w := httptest.NewRecorder()

	setSessionCookie(w, r, "sess-456")

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	require.False(t, cookies[0].Secure)
	require.Equal(t, http.SameSiteLaxMode, cookies[0].SameSite)
}

// TestSetSessionCookie_ForwardedHTTPS covers the TLS-terminated-upstream case (X-Forwarded-Proto) getting the same SameSite=None+Secure treatment.
func TestSetSessionCookie_ForwardedHTTPS(t *testing.T) {
	r := httptest.NewRequest("GET", "http://broker.internal/auth/verify/abc", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()

	setSessionCookie(w, r, "sess-789")

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	require.True(t, cookies[0].Secure)
	require.Equal(t, http.SameSiteNoneMode, cookies[0].SameSite)
}
