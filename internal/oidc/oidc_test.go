package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// fakeIdP is a minimal OIDC provider whose /token response's amr claim is configurable.
type fakeIdP struct {
	key    *rsa.PrivateKey
	issuer string
	amr    []string
	pkce   string
}

func newFakeIdP(t *testing.T, amr []string) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeIdP{key: key, amr: amr}
}

func (f *fakeIdP) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": f.issuer, "authorization_endpoint": f.issuer + "/authorize",
			"token_endpoint": f.issuer + "/token", "jwks_uri": f.issuer + "/jwks.json",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		n := base64.RawURLEncoding.EncodeToString(f.key.PublicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(f.key.PublicKey.E)).Bytes())
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "k", "n": n, "e": e,
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if got := sha256Base64(r.FormValue("code_verifier")); got != f.pkce {
			http.Error(w, "invalid_grant", http.StatusBadRequest)
			return
		}
		now := time.Now()
		claims := jwt.MapClaims{
			"iss": f.issuer, "aud": "client-1", "sub": "sub-1",
			"exp": now.Add(time.Minute).Unix(), "iat": now.Unix(),
			"preferred_username": "alice",
		}
		if f.amr != nil {
			claims["amr"] = f.amr
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = "k"
		signed, err := tok.SignedString(f.key)
		if err != nil {
			http.Error(w, "server_error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "id_token": signed, "token_type": "Bearer", "expires_in": 3600})
	})
	return mux
}

func sha256Base64(s string) string {
	sum := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func exchangeWithAMR(t *testing.T, tokenAMR, required []string) error {
	t.Helper()
	idp := newFakeIdP(t, tokenAMR)
	srv := httptest.NewServer(idp.handler())
	defer srv.Close()
	idp.issuer = srv.URL
	idp.pkce = sha256Base64("verifier-1")

	provider, err := New(context.Background(), Config{
		IssuerURL: idp.issuer, ClientID: "client-1", ClientSecret: "s",
		RedirectURL: "http://broker.example/auth/callback", RequiredAMR: required,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = provider.Exchange(context.Background(), "code-1", PKCEPair{Verifier: "verifier-1"}, "")
	return err
}

func TestExchange_RequiredAMRAcceptsMatchingToken(t *testing.T) {
	if err := exchangeWithAMR(t, []string{"pwd", "hwk"}, []string{"hwk", "swk"}); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
}

func TestExchange_RequiredAMRRejectsNonMatchingToken(t *testing.T) {
	err := exchangeWithAMR(t, []string{"pwd"}, []string{"hwk", "swk"})
	if err == nil {
		t.Fatal("expected an error when the token lacks a required amr value")
	}
}

func TestExchange_NoRequiredAMRAcceptsAnyToken(t *testing.T) {
	if err := exchangeWithAMR(t, nil, nil); err != nil {
		t.Fatalf("expected success when RequiredAMR is unset, got %v", err)
	}
}

func TestAmrSatisfies_MatchesOneOfRequired(t *testing.T) {
	claims := map[string]any{"amr": []any{"pwd", "hwk"}}
	if !amrSatisfies(claims, []string{"hwk", "swk"}) {
		t.Fatal("expected hwk to satisfy required amr")
	}
}

func TestAmrSatisfies_NoOverlapFails(t *testing.T) {
	claims := map[string]any{"amr": []any{"pwd", "otp"}}
	if amrSatisfies(claims, []string{"hwk", "swk"}) {
		t.Fatal("expected password+otp to not satisfy hwk/swk requirement")
	}
}

func TestAmrSatisfies_MissingClaimFails(t *testing.T) {
	claims := map[string]any{}
	if amrSatisfies(claims, []string{"hwk"}) {
		t.Fatal("expected missing amr claim to fail closed")
	}
}

func TestAmrSatisfies_WrongTypeFails(t *testing.T) {
	claims := map[string]any{"amr": "hwk"} // not a list, per spec it should be
	if amrSatisfies(claims, []string{"hwk"}) {
		t.Fatal("expected non-array amr claim to fail closed")
	}
}

func TestAmrSatisfies_EmptyRequiredNeverMatches(t *testing.T) {
	claims := map[string]any{"amr": []any{"hwk"}}
	if amrSatisfies(claims, nil) {
		t.Fatal("empty required list should never be satisfied by this helper (caller skips the check instead)")
	}
}
