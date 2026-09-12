// Package saml is the broker's SAML 2.0 service-provider leg, an alternative to package oidc.
package saml

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"time"

	crewjamsaml "github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"

	"github.com/rupivbluegreen/xdauth/internal/store"
)

// Config configures the broker's SAML service provider.
type Config struct {
	EntityID          string // defaults to BaseURL
	BaseURL           string // this broker's own base URL; ACS is BaseURL + "/auth/saml/acs" unless ACSURL is set
	ACSURL            string // optional: overrides the default ACS URL, e.g. to match an SP already registered with the IdP under a different URL
	IDPMetadataURL    string // fetch IdP metadata from here at New(); mutually exclusive with IDPMetadataXML
	IDPMetadataXML    []byte // IdP metadata document, e.g. read from a local file by the caller
	IdentityAttribute string // SAML attribute read as the identity value; empty means use the NameID
	HTTPClient        *http.Client
}

// Provider is the broker's SAML confidential-style service provider (it holds a self-signed
// signing key, though nothing in the default unsigned-request/unencrypted-assertion path needs it).
type Provider struct {
	sp                crewjamsaml.ServiceProvider
	identityAttribute string
}

// New fetches or parses the IdP metadata and returns a ready Provider.
func New(ctx context.Context, cfg Config) (*Provider, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("saml: BaseURL is required")
	}
	if (cfg.IDPMetadataURL == "") == (len(cfg.IDPMetadataXML) == 0) {
		return nil, fmt.Errorf("saml: exactly one of IDPMetadataURL or IDPMetadataXML is required")
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	var idpMetadata *crewjamsaml.EntityDescriptor
	if cfg.IDPMetadataURL != "" {
		u, err := url.Parse(cfg.IDPMetadataURL)
		if err != nil {
			return nil, fmt.Errorf("saml: parse IDPMetadataURL: %w", err)
		}
		idpMetadata, err = samlsp.FetchMetadata(ctx, httpClient, *u)
		if err != nil {
			return nil, fmt.Errorf("saml: fetch idp metadata: %w", err)
		}
	} else {
		var err error
		idpMetadata, err = samlsp.ParseMetadata(cfg.IDPMetadataXML)
		if err != nil {
			return nil, fmt.Errorf("saml: parse idp metadata: %w", err)
		}
	}

	key, cert, err := selfSignedCert(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("saml: generate sp signing cert: %w", err)
	}

	entityID := cfg.EntityID
	if entityID == "" {
		entityID = cfg.BaseURL
	}
	acsURLStr := cfg.ACSURL
	if acsURLStr == "" {
		acsURLStr = cfg.BaseURL + "/auth/saml/acs"
	}
	acsURL, err := url.Parse(acsURLStr)
	if err != nil {
		return nil, fmt.Errorf("saml: parse ACS URL: %w", err)
	}
	metadataURL, err := url.Parse(cfg.BaseURL + "/auth/saml/metadata")
	if err != nil {
		return nil, fmt.Errorf("saml: parse BaseURL: %w", err)
	}

	sp := crewjamsaml.ServiceProvider{
		EntityID:    entityID,
		Key:         key,
		Certificate: cert,
		HTTPClient:  httpClient,
		MetadataURL: *metadataURL,
		AcsURL:      *acsURL,
		IDPMetadata: idpMetadata,
	}

	return &Provider{sp: sp, identityAttribute: cfg.IdentityAttribute}, nil
}

// Metadata returns this SP's own metadata, for registering with an IdP.
func (p *Provider) Metadata() *crewjamsaml.EntityDescriptor {
	return p.sp.Metadata()
}

// BeginLogin implements broker.IdentityProvider: it stores this leg's AuthnRequest ID on sess.
func (p *Provider) BeginLogin(sess *store.Session) (string, error) {
	idpSSOURL := p.sp.GetSSOBindingLocation(crewjamsaml.HTTPRedirectBinding)
	if idpSSOURL == "" {
		return "", fmt.Errorf("saml: idp metadata has no HTTP-Redirect SSO binding")
	}
	req, err := p.sp.MakeAuthenticationRequest(idpSSOURL, crewjamsaml.HTTPRedirectBinding, crewjamsaml.HTTPPostBinding)
	if err != nil {
		return "", fmt.Errorf("saml: make authentication request: %w", err)
	}

	sess.SAMLRequestID = req.ID
	sess.Protocol = "saml"

	redirectURL, err := req.Redirect(sess.ID, &p.sp)
	if err != nil {
		return "", fmt.Errorf("saml: build redirect: %w", err)
	}
	return redirectURL.String(), nil
}

// CompleteLogin implements broker.IdentityProvider: it checks RelayState, then validates the assertion.
func (p *Provider) CompleteLogin(_ context.Context, r *http.Request, sess *store.Session) (store.Identity, error) {
	if err := r.ParseForm(); err != nil {
		return store.Identity{}, fmt.Errorf("saml: parse form: %w", err)
	}
	if relayState := r.PostFormValue("RelayState"); relayState == "" || relayState != sess.ID {
		return store.Identity{}, fmt.Errorf("saml: RelayState mismatch")
	}

	assertion, err := p.sp.ParseResponse(r, []string{sess.SAMLRequestID})
	if err != nil {
		return store.Identity{}, fmt.Errorf("saml: parse response: %w", err)
	}
	return identityFromAssertion(assertion, p.identityAttribute)
}

// identityFromAssertion picks the identity value (NameID, or a named attribute) and flattens every
// attribute into the artifact's Claims. Split out from CompleteLogin so it's unit-testable without
// a signed XML round trip; ParseResponse above is what actually verifies the assertion's signature.
func identityFromAssertion(assertion *crewjamsaml.Assertion, identityAttribute string) (store.Identity, error) {
	claims := attributeClaims(assertion)

	value := ""
	if identityAttribute == "" {
		if assertion.Subject == nil || assertion.Subject.NameID == nil {
			return store.Identity{}, fmt.Errorf("saml: assertion has no NameID")
		}
		value = assertion.Subject.NameID.Value
	} else {
		v, ok := claims[identityAttribute]
		if !ok || len(v) == 0 || v[0] == "" {
			return store.Identity{}, fmt.Errorf("saml: attribute %q missing or empty", identityAttribute)
		}
		value = v[0]
	}

	genericClaims := make(map[string]any, len(claims))
	for k, v := range claims {
		if len(v) == 1 {
			genericClaims[k] = v[0]
		} else {
			genericClaims[k] = v
		}
	}

	subject := assertion.ID
	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		subject = assertion.Subject.NameID.Value
	}

	return store.Identity{Subject: subject, Value: value, Claims: genericClaims}, nil
}

// attributeClaims flattens every AttributeStatement into name -> values.
func attributeClaims(assertion *crewjamsaml.Assertion) map[string][]string {
	out := map[string][]string{}
	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			name := attr.FriendlyName
			if name == "" {
				name = attr.Name
			}
			for _, v := range attr.Values {
				out[name] = append(out[name], v.Value)
			}
		}
	}
	return out
}

// selfSignedCert generates a throwaway SP signing key/cert. Nothing in the default unsigned-request,
// unencrypted-assertion path uses it; it exists so Metadata() publishes a complete SPSSODescriptor.
func selfSignedCert(baseURL string) (*rsa.PrivateKey, *x509.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: baseURL},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return key, cert, nil
}
