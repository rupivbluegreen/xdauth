// Package client is a small Go library for the xdauth cross-device login flow.
package client

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// StartRequest is what the caller supplies to begin a login.
type StartRequest struct {
	BrokerURL  string // e.g. "https://xdauth.example.com", no trailing slash
	LoginHint  string
	ClientKind string // e.g. "cli", "ssh"
	ClientHost string
	HTTPClient *http.Client // optional; defaults to a client with a 10s timeout
}

// Session is the result of Start; the PKCE verifier is held but never exposed outside this package.
type Session struct {
	ID              string
	VerificationURI string
	UserCode        string
	ExpiresIn       time.Duration
	Interval        time.Duration

	brokerURL string
	verifier  string
	httpc     *http.Client
}

type startWireRequest struct {
	LoginHint           string `json:"login_hint"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	ClientKind          string `json:"client_kind"`
	ClientHost          string `json:"client_host"`
}

type startWireResponse struct {
	SessionID       string `json:"session_id"`
	VerificationURI string `json:"verification_uri"`
	UserCode        string `json:"user_code"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
	Error           string `json:"error"`
}

// Start creates a new session with the broker, generating a fresh PKCE pair internally.
func Start(ctx context.Context, req StartRequest) (*Session, error) {
	if req.BrokerURL == "" || req.LoginHint == "" {
		return nil, fmt.Errorf("xdauth/client: BrokerURL and LoginHint are required")
	}
	httpc := req.HTTPClient
	if httpc == nil {
		httpc = &http.Client{Timeout: 10 * time.Second}
	}

	verifier, challenge, err := newPKCEPair()
	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(startWireRequest{
		LoginHint:           req.LoginHint,
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		ClientKind:          req.ClientKind,
		ClientHost:          req.ClientHost,
	})
	if err != nil {
		return nil, fmt.Errorf("xdauth/client: encode start request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(req.BrokerURL, "/")+"/auth/start", strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("xdauth/client: build start request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := httpc.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("xdauth/client: start request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var wire startWireResponse
	if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil {
		return nil, fmt.Errorf("xdauth/client: decode start response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("xdauth/client: start failed: %s", wire.Error)
	}

	return &Session{
		ID:              wire.SessionID,
		VerificationURI: wire.VerificationURI,
		UserCode:        wire.UserCode,
		ExpiresIn:       time.Duration(wire.ExpiresIn) * time.Second,
		Interval:        time.Duration(wire.Interval) * time.Second,
		brokerURL:       strings.TrimRight(req.BrokerURL, "/"),
		verifier:        verifier,
		httpc:           httpc,
	}, nil
}

// Artifact is what a successful login releases.
type Artifact struct {
	Subject    string         `json:"subject"`
	Identity   string         `json:"identity"`
	Claims     map[string]any `json:"claims"`
	ApprovedAt time.Time      `json:"approved_at"`
	ExpiresAt  time.Time      `json:"expires_at"`
}

// Result is the terminal outcome of Poll.
type Result struct {
	Status   string // "approved", "denied", or "expired"
	Artifact *Artifact
}

type pollWireRequest struct {
	SessionID    string `json:"session_id"`
	CodeVerifier string `json:"code_verifier"`
}

type pollWireResponse struct {
	Status   string    `json:"status"`
	Artifact *Artifact `json:"artifact"`
	Error    string    `json:"error"`
}

// Poll blocks until the session reaches a terminal state or ctx is done, honouring slow_down.
func Poll(ctx context.Context, sess *Session) (*Result, error) {
	interval := sess.Interval
	if interval <= 0 {
		interval = 3 * time.Second
	}
	timer := time.NewTimer(0) // poll immediately once
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
		}

		status, artifact, err := sess.pollOnce(ctx)
		if err != nil {
			return nil, err
		}
		switch status {
		case "pending":
			timer.Reset(interval)
		case "slow_down":
			interval += interval / 2
			timer.Reset(interval)
		case "approved", "denied", "expired":
			return &Result{Status: status, Artifact: artifact}, nil
		default:
			return nil, fmt.Errorf("xdauth/client: unexpected status %q", status)
		}
	}
}

func (s *Session) pollOnce(ctx context.Context) (string, *Artifact, error) {
	body, err := json.Marshal(pollWireRequest{SessionID: s.ID, CodeVerifier: s.verifier})
	if err != nil {
		return "", nil, fmt.Errorf("xdauth/client: encode poll request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.brokerURL+"/auth/poll", strings.NewReader(string(body)))
	if err != nil {
		return "", nil, fmt.Errorf("xdauth/client: build poll request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := s.httpc.Do(httpReq)
	if err != nil {
		return "", nil, fmt.Errorf("xdauth/client: poll request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var wire pollWireResponse
	if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil {
		return "", nil, fmt.Errorf("xdauth/client: decode poll response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("xdauth/client: poll failed: %s", wire.Error)
	}
	return wire.Status, wire.Artifact, nil
}

func newPKCEPair() (verifier, challenge string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("xdauth/client: generate pkce verifier: %w", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}
