// Package oidc wraps the broker's confidential-client Authorization Code + PKCE exchange with any OIDC provider.
package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/rupivbluegreen/xdauth/internal/store"
)

// Config configures the broker's OIDC client.
type Config struct {
	IssuerURL     string
	ClientID      string
	ClientSecret  string
	RedirectURL   string
	Scopes        []string // "openid" is added automatically if missing
	IdentityClaim string   // ID-token claim read as the identity value, e.g. "preferred_username"
}

// Provider is the broker's confidential OIDC client.
type Provider struct {
	cfg      Config
	oauth2   oauth2.Config
	verifier *gooidc.IDTokenVerifier
}

// New discovers the issuer's configuration and returns a ready Provider.
func New(ctx context.Context, cfg Config) (*Provider, error) {
	if cfg.IdentityClaim == "" {
		cfg.IdentityClaim = "preferred_username"
	}
	hasOpenID := false
	for _, s := range cfg.Scopes {
		if s == gooidc.ScopeOpenID {
			hasOpenID = true
			break
		}
	}
	if !hasOpenID {
		cfg.Scopes = append([]string{gooidc.ScopeOpenID}, cfg.Scopes...)
	}

	p, err := gooidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("discover issuer: %w", err)
	}

	return &Provider{
		cfg: cfg,
		oauth2: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     p.Endpoint(),
			Scopes:       cfg.Scopes,
		},
		verifier: p.Verifier(&gooidc.Config{ClientID: cfg.ClientID}),
	}, nil
}

// PKCEPair is the broker's own PKCE pair for its IdP leg, unrelated to the client's PKCE pair.
type PKCEPair struct {
	Verifier  string
	Challenge string
}

// NewPKCEPair generates a fresh S256 PKCE pair.
func NewPKCEPair() (PKCEPair, error) {
	verifier := oauth2.GenerateVerifier()
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	return PKCEPair{Verifier: verifier, Challenge: challenge}, nil
}

// AuthCodeURL builds the URL the browser is redirected to.
func (p *Provider) AuthCodeURL(state, nonce string, pkce PKCEPair) string {
	return p.oauth2.AuthCodeURL(state,
		oidcNonce(nonce),
		oauth2.S256ChallengeOption(pkce.Verifier),
	)
}

// oidcNonce renders the nonce as an auth-code URL parameter.
func oidcNonce(nonce string) oauth2.AuthCodeOption {
	return oauth2.SetAuthURLParam("nonce", nonce)
}

// Identity is the result of a successful exchange.
type Identity struct {
	Subject string
	Value   string
	Claims  map[string]any
}

// Exchange swaps code for tokens, verifies the ID token, and extracts the identity.
func (p *Provider) Exchange(ctx context.Context, code string, pkce PKCEPair, expectedNonce string) (*Identity, error) {
	tok, err := p.oauth2.Exchange(ctx, code, oauth2.VerifierOption(pkce.Verifier))
	if err != nil {
		return nil, fmt.Errorf("code exchange: %w", err)
	}

	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, fmt.Errorf("token response carried no id_token")
	}

	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("id_token verification: %w", err)
	}
	if idToken.Nonce != expectedNonce {
		return nil, fmt.Errorf("id_token nonce mismatch")
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}

	value, _ := claims[p.cfg.IdentityClaim].(string)
	if value == "" {
		return nil, fmt.Errorf("identity claim %q missing or empty", p.cfg.IdentityClaim)
	}

	return &Identity{Subject: idToken.Subject, Value: value, Claims: claims}, nil
}

// BeginLogin implements broker.IdentityProvider: it stores this leg's PKCE/state/nonce on sess.
func (p *Provider) BeginLogin(sess *store.Session) (string, error) {
	pkce, err := NewPKCEPair()
	if err != nil {
		return "", err
	}
	state := oauth2.GenerateVerifier()
	nonce := oauth2.GenerateVerifier()
	sess.IdPState = state
	sess.IdPNonce = nonce
	sess.IdPPKCEVerifier = pkce.Verifier
	sess.Protocol = "oidc"
	return p.AuthCodeURL(state, nonce, pkce), nil
}

// CompleteLogin implements broker.IdentityProvider: it checks state, then exchanges the code.
func (p *Provider) CompleteLogin(ctx context.Context, r *http.Request, sess *store.Session) (store.Identity, error) {
	q := r.URL.Query()
	if q.Get("state") == "" || q.Get("state") != sess.IdPState {
		return store.Identity{}, fmt.Errorf("state mismatch")
	}
	code := q.Get("code")
	if code == "" {
		return store.Identity{}, fmt.Errorf("identity provider did not return an authorization code")
	}
	ident, err := p.Exchange(ctx, code, PKCEPair{Verifier: sess.IdPPKCEVerifier}, sess.IdPNonce)
	if err != nil {
		return store.Identity{}, err
	}
	return store.Identity{Subject: ident.Subject, Value: ident.Value, Claims: ident.Claims}, nil
}
