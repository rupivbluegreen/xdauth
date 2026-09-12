package broker

import (
	"context"
	"net/http"

	"github.com/rupivbluegreen/xdauth/internal/store"
)

// IdentityProvider begins and completes a browser-based login with an upstream IdP, OIDC or SAML.
// *oidc.Provider and *saml.Provider both satisfy this without any adapter type.
type IdentityProvider interface {
	// BeginLogin stores whatever correlation state this protocol needs on sess and returns the
	// URL to redirect the browser to.
	BeginLogin(sess *store.Session) (redirectURL string, err error)
	// CompleteLogin validates the IdP's response against sess's stored correlation state and
	// returns the verified identity.
	CompleteLogin(ctx context.Context, r *http.Request, sess *store.Session) (store.Identity, error)
}
