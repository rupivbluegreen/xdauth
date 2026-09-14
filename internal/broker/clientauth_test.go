package broker

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStaticTokenClientAuth_AcceptsKnownToken(t *testing.T) {
	a := StaticTokenClientAuth{Tokens: map[string]string{"tok-abc": "client-1"}}
	r := httptest.NewRequest("POST", "/auth/start", nil)
	r.Header.Set("Authorization", "Bearer tok-abc")

	id, err := a.Authenticate(r)
	require.NoError(t, err)
	assert.Equal(t, "client-1", id)
}

func TestStaticTokenClientAuth_RejectsUnknownToken(t *testing.T) {
	a := StaticTokenClientAuth{Tokens: map[string]string{"tok-abc": "client-1"}}
	r := httptest.NewRequest("POST", "/auth/start", nil)
	r.Header.Set("Authorization", "Bearer wrong")

	_, err := a.Authenticate(r)
	require.ErrorIs(t, err, ErrClientNotAuthenticated)
}

func TestStaticTokenClientAuth_RejectsMissingHeader(t *testing.T) {
	a := StaticTokenClientAuth{Tokens: map[string]string{"tok-abc": "client-1"}}
	r := httptest.NewRequest("POST", "/auth/start", nil)

	_, err := a.Authenticate(r)
	require.ErrorIs(t, err, ErrClientNotAuthenticated)
}

func TestMTLSClientAuth_UsesPeerCertificateCommonName(t *testing.T) {
	r := httptest.NewRequest("POST", "/auth/start", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{
		{Subject: pkix.Name{CommonName: "bastion-01"}},
	}}

	id, err := MTLSClientAuth{}.Authenticate(r)
	require.NoError(t, err)
	assert.Equal(t, "bastion-01", id)
}

func TestMTLSClientAuth_RejectsPlainHTTP(t *testing.T) {
	r := httptest.NewRequest("POST", "/auth/start", nil)
	_, err := MTLSClientAuth{}.Authenticate(r)
	require.ErrorIs(t, err, ErrClientNotAuthenticated)
}
