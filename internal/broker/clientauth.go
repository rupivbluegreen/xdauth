package broker

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
)

// ErrClientNotAuthenticated: /auth/start was called without valid client credentials.
var ErrClientNotAuthenticated = errors.New("client authentication failed")

// ClientAuthenticator verifies the caller of /auth/start (mitigations 7, 15).
type ClientAuthenticator interface {
	Authenticate(r *http.Request) (clientID string, err error)
}

// StaticTokenClientAuth maps a pre-shared bearer token to a client identity.
type StaticTokenClientAuth struct {
	Tokens map[string]string // token -> client id
}

func (a StaticTokenClientAuth) Authenticate(r *http.Request) (string, error) {
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, prefix) {
		return "", ErrClientNotAuthenticated
	}
	token := strings.TrimPrefix(auth, prefix)
	for known, id := range a.Tokens {
		if subtle.ConstantTimeCompare([]byte(token), []byte(known)) == 1 {
			return id, nil
		}
	}
	return "", ErrClientNotAuthenticated
}

// MTLSClientAuth trusts the CommonName of the client's TLS certificate.
type MTLSClientAuth struct{}

func (MTLSClientAuth) Authenticate(r *http.Request) (string, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", ErrClientNotAuthenticated
	}
	return r.TLS.PeerCertificates[0].Subject.CommonName, nil
}
