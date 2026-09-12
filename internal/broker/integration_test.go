package broker

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/rupivbluegreen/xdauth/internal/oidc"
	"github.com/rupivbluegreen/xdauth/internal/store"
)

// fakeIdP is a minimal OIDC provider that auto-authenticates every /authorize request as a fixed username.
type fakeIdP struct {
	key      *rsa.PrivateKey
	issuer   string
	username string
	pending  map[string]pendingAuth
}

type pendingAuth struct {
	nonce         string
	codeChallenge string
	clientID      string
	redirectURI   string
}

func newFakeIdP(username string) *fakeIdP {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return &fakeIdP{key: key, username: username, pending: map[string]pendingAuth{}}
}

func (f *fakeIdP) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", f.discovery)
	mux.HandleFunc("/jwks.json", f.jwks)
	mux.HandleFunc("/authorize", f.authorize)
	mux.HandleFunc("/token", f.token)
	return mux
}

func (f *fakeIdP) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSONTest(w, map[string]any{
		"issuer":                                f.issuer,
		"authorization_endpoint":                f.issuer + "/authorize",
		"token_endpoint":                        f.issuer + "/token",
		"jwks_uri":                              f.issuer + "/jwks.json",
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (f *fakeIdP) jwks(w http.ResponseWriter, _ *http.Request) {
	n := base64.RawURLEncoding.EncodeToString(f.key.PublicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(f.key.PublicKey.E)).Bytes())
	writeJSONTest(w, map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "test-key", "n": n, "e": e,
	}}})
}

// authorize skips any real login UI and redirects straight back with a code, as if the user just approved.
func (f *fakeIdP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	code := fmt.Sprintf("code-%d", time.Now().UnixNano())
	f.pending[code] = pendingAuth{
		nonce:         q.Get("nonce"),
		codeChallenge: q.Get("code_challenge"),
		clientID:      q.Get("client_id"),
		redirectURI:   q.Get("redirect_uri"),
	}
	http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+q.Get("state"), http.StatusFound)
}

func (f *fakeIdP) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	code := r.FormValue("code")
	verifier := r.FormValue("code_verifier")
	p, ok := f.pending[code]
	if !ok {
		http.Error(w, "invalid_grant", http.StatusBadRequest)
		return
	}
	delete(f.pending, code)

	sum := sha256.Sum256([]byte(verifier))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != p.codeChallenge {
		http.Error(w, "invalid_grant: pkce mismatch", http.StatusBadRequest)
		return
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": f.issuer, "aud": p.clientID, "sub": "sub-" + f.username,
		"exp": now.Add(time.Minute).Unix(), "iat": now.Unix(),
		"nonce": p.nonce, "preferred_username": f.username,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = "test-key"
	signed, err := tok.SignedString(f.key)
	if err != nil {
		http.Error(w, "server_error", http.StatusInternalServerError)
		return
	}

	writeJSONTest(w, map[string]any{
		"access_token": "test-access-token", "id_token": signed,
		"token_type": "Bearer", "expires_in": 3600,
	})
}

func writeJSONTest(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// TestIntegration_EndToEndApproval drives the broker's real HTTP handlers against a fake OIDC provider.
func TestIntegration_EndToEndApproval(t *testing.T) {
	ctx := context.Background()
	idp := newFakeIdP("alice")
	idpServer := httptest.NewServer(idp.handler())
	defer idpServer.Close()
	idp.issuer = idpServer.URL

	// NewUnstartedServer binds the listener (so its URL is known) before the handler must exist,
	// which lets the provider's RedirectURL point at the broker's own real address.
	var realHandler http.Handler
	brokerServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		realHandler.ServeHTTP(w, r)
	}))
	brokerURL := "http://" + brokerServer.Listener.Addr().String()
	defer brokerServer.Close()

	provider, err := oidc.New(ctx, oidc.Config{
		IssuerURL:    idp.issuer,
		ClientID:     "xdauth-test",
		ClientSecret: "test-secret",
		RedirectURL:  brokerURL + "/auth/callback",
	})
	require.NoError(t, err)

	sessionStore := store.NewMemory(time.Minute)
	defer sessionStore.Close()
	b := New(Config{BaseURL: brokerURL, Logger: slog.Default()}, sessionStore, provider)
	realHandler = b.Router()
	brokerServer.Start()

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{Jar: jar}

	startBody := fmt.Sprintf(`{"login_hint":"alice","code_challenge":"%s","code_challenge_method":"S256","client_kind":"cli","client_host":"test-host"}`, challengeFor("client-verifier"))
	startResp, err := client.Post(brokerServer.URL+"/auth/start", "application/json", strings.NewReader(startBody))
	require.NoError(t, err)
	var start startResponse
	require.NoError(t, json.NewDecoder(startResp.Body).Decode(&start))
	startResp.Body.Close()
	require.NotEmpty(t, start.SessionID)

	verifyResp, err := client.Get(start.VerificationURI)
	require.NoError(t, err)
	verifyResp.Body.Close()

	sess, err := sessionStore.Get(ctx, start.SessionID)
	require.NoError(t, err)
	require.Equal(t, store.StateAwaitingApproval, sess.State)

	approveResp, err := client.PostForm(brokerServer.URL+"/auth/approve", map[string][]string{
		"csrf_token": {sess.CSRFToken}, "user_code": {start.UserCode}, "decision": {"approve"},
	})
	require.NoError(t, err)
	approveResp.Body.Close()

	pollBody := fmt.Sprintf(`{"session_id":"%s","code_verifier":"client-verifier"}`, start.SessionID)
	pollResp, err := client.Post(brokerServer.URL+"/auth/poll", "application/json", strings.NewReader(pollBody))
	require.NoError(t, err)
	var poll pollResponse
	require.NoError(t, json.NewDecoder(pollResp.Body).Decode(&poll))
	pollResp.Body.Close()

	require.Equal(t, "approved", poll.Status)
	require.NotNil(t, poll.Artifact)
	require.Equal(t, "alice", poll.Artifact.Identity)
}
