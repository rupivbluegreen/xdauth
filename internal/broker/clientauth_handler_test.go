package broker

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/rupivbluegreen/xdauth/internal/store"
)

// fakeNoopIdP satisfies IdentityProvider without ever completing a login.
type fakeNoopIdP struct{}

func (fakeNoopIdP) BeginLogin(*store.Session) (string, error) { return "", nil }
func (fakeNoopIdP) CompleteLogin(context.Context, *http.Request, *store.Session) (store.Identity, error) {
	return store.Identity{}, nil
}

func TestHandleStart_RejectsUnauthenticatedClientWhenGated(t *testing.T) {
	st := store.NewMemory(time.Minute)
	defer st.Close()
	b := New(Config{
		BaseURL:             "http://broker.example",
		Logger:              slog.Default(),
		ClientAuthenticator: StaticTokenClientAuth{Tokens: map[string]string{"good-token": "bastion-01"}},
	}, st, fakeNoopIdP{})

	body := `{"login_hint":"alice","code_challenge":"c","code_challenge_method":"S256"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/start", strings.NewReader(body))
	rec := httptest.NewRecorder()
	b.Router().ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandleStart_AcceptsAuthenticatedClientAndRecordsIt(t *testing.T) {
	st := store.NewMemory(time.Minute)
	defer st.Close()
	b := New(Config{
		BaseURL:             "http://broker.example",
		Logger:              slog.Default(),
		ClientAuthenticator: StaticTokenClientAuth{Tokens: map[string]string{"good-token": "bastion-01"}},
	}, st, fakeNoopIdP{})

	body := `{"login_hint":"alice","code_challenge":"c","code_challenge_method":"S256"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/start", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer good-token")
	rec := httptest.NewRecorder()
	b.Router().ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp startResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	sess, err := st.Get(req.Context(), resp.SessionID)
	require.NoError(t, err)
	require.Equal(t, "bastion-01", sess.VerifiedClient)
}
