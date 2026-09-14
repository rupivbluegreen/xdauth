package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// fakeBroker is a minimal stand-in for the real broker: /auth/poll stays "pending" until approve() is called.
type fakeBroker struct {
	approved atomic.Bool
}

func (f *fakeBroker) approve() { f.approved.Store(true) }

func (f *fakeBroker) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/start", func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, map[string]any{
			"session_id":       "sess-1",
			"verification_uri": "http://example.invalid/auth/verify/sess-1",
			"user_code":        "ABCD-1234",
			"expires_in":       300,
			"interval":         1,
		})
	})
	mux.HandleFunc("/auth/poll", func(w http.ResponseWriter, _ *http.Request) {
		if !f.approved.Load() {
			writeTestJSON(w, map[string]any{"status": "pending"})
			return
		}
		writeTestJSON(w, map[string]any{
			"status": "approved",
			"artifact": map[string]any{
				"subject":  "sub-alice",
				"identity": "alice",
				"claims":   map[string]any{},
			},
		})
	})
	return mux
}

func writeTestJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func testLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// startTestServer boots an xdauth-sshd instance against brokerURL on a loopback port and returns its address.
func startTestServer(t *testing.T, ctx context.Context, brokerURL string) string {
	t.Helper()
	hostKey, err := loadOrGenerateHostKey("")
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	config := newServerConfig(ctx, brokerURL, testLogger())
	config.AddHostKey(hostKey)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go serve(ctx, listener, config, "demo shell", testLogger())
	return listener.Addr().String()
}

// TestKeyboardInteractive_ChallengeDeliveredBeforeApproval proves the info message reaches the SSH client
// while the broker session is still pending, not merely "eventually" once approval also lands.
func TestKeyboardInteractive_ChallengeDeliveredBeforeApproval(t *testing.T) {
	broker := &fakeBroker{}
	brokerServer := httptest.NewServer(broker.handler())
	defer brokerServer.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := startTestServer(t, ctx, brokerServer.URL)

	challengeCh := make(chan time.Time, 1)
	clientConfig := &ssh.ClientConfig{
		User: "alice",
		Auth: []ssh.AuthMethod{
			ssh.KeyboardInteractive(func(_, _ string, _ []string, _ []bool) ([]string, error) {
				challengeCh <- time.Now()
				return []string{}, nil
			}),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // #nosec G106 -- test dials its own ephemeral local server
		Timeout:         5 * time.Second,
	}

	dialDone := make(chan error, 1)
	go func() {
		conn, err := ssh.Dial("tcp", addr, clientConfig)
		if err == nil {
			_ = conn.Close()
		}
		dialDone <- err
	}()

	var challengeAt time.Time
	select {
	case challengeAt = <-challengeCh:
	case <-time.After(5 * time.Second):
		t.Fatal("did not receive the keyboard-interactive challenge in time")
	}

	// the broker must still be pending at this point: approval only happens after this check, below.
	if broker.approved.Load() {
		t.Fatal("broker session was already approved before the challenge was delivered")
	}
	approvedAt := time.Now()
	broker.approve()

	select {
	case err := <-dialDone:
		if err != nil {
			t.Fatalf("ssh dial: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ssh dial did not complete after approval")
	}

	if !challengeAt.Before(approvedAt) {
		t.Fatalf("challenge delivered at %v, not before approval at %v", challengeAt, approvedAt)
	}
}

// TestKeyboardInteractive_DeniedFailsClosed proves a non-approved outcome rejects the connection instead of letting it through.
func TestKeyboardInteractive_DeniedFailsClosed(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/start", func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, map[string]any{
			"session_id": "sess-2", "verification_uri": "http://example.invalid/auth/verify/sess-2",
			"user_code": "WXYZ-9999", "expires_in": 300, "interval": 1,
		})
	})
	mux.HandleFunc("/auth/poll", func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, map[string]any{"status": "denied"})
	})
	brokerServer := httptest.NewServer(mux)
	defer brokerServer.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := startTestServer(t, ctx, brokerServer.URL)

	clientConfig := &ssh.ClientConfig{
		User: "mallory",
		Auth: []ssh.AuthMethod{
			ssh.KeyboardInteractive(func(_, _ string, _ []string, _ []bool) ([]string, error) {
				return []string{}, nil
			}),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // #nosec G106 -- test dials its own ephemeral local server
		Timeout:         5 * time.Second,
	}

	if _, err := ssh.Dial("tcp", addr, clientConfig); err == nil {
		t.Fatal("expected ssh dial to fail for a denied session, got nil error")
	}
}
