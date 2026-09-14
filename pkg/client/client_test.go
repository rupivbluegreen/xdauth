package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestPoll_ArtifactExpiryRoundTrips: ExpiresAt survives the wire round trip.
func TestPoll_ArtifactExpiryRoundTrips(t *testing.T) {
	expiresAt := time.Now().Add(2 * time.Minute).UTC().Truncate(time.Second)
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/start", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(startWireResponse{
			SessionID: "s1", VerificationURI: "http://example/v/s1",
			UserCode: "ABCD-1234", ExpiresIn: 300, Interval: 0,
		})
	})
	mux.HandleFunc("/auth/poll", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(pollWireResponse{
			Status: "approved",
			Artifact: &Artifact{
				Subject: "sub-1", Identity: "alice",
				ApprovedAt: time.Now(), ExpiresAt: expiresAt,
			},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	sess, err := Start(t.Context(), StartRequest{BrokerURL: srv.URL, LoginHint: "alice"})
	require.NoError(t, err)

	result, err := Poll(t.Context(), sess)
	require.NoError(t, err)
	require.Equal(t, "approved", result.Status)
	require.NotNil(t, result.Artifact)
	require.True(t, result.Artifact.ExpiresAt.Equal(expiresAt))
	require.True(t, result.Artifact.ExpiresAt.After(result.Artifact.ApprovedAt))
}
