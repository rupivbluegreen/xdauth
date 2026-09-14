// Package store defines the session model and storage interface the broker uses.
package store

import (
	"context"
	"errors"
	"sync"
	"time"
)

// State is the session's position in the state machine.
type State string

const (
	StatePending          State = "pending"           // created, no identity bound yet
	StateAwaitingApproval State = "awaiting_approval" // identity bound, waiting on the user code
	StateApproved         State = "approved"          // terminal: all four checks passed
	StateDenied           State = "denied"            // terminal: declined or too many wrong codes
	StateExpired          State = "expired"           // terminal: TTL elapsed before approval
)

// ErrNotFound is returned when a session id has no matching session.
var ErrNotFound = errors.New("session not found")

// Identity is what the IdP callback bound to the session.
type Identity struct {
	Subject string
	Value   string // the configured identity claim, e.g. preferred_username
	Claims  map[string]any
}

// Session is one cross-device login attempt.
type Session struct {
	ID string

	LoginHint      string
	CodeChallenge  string // client's PKCE code_challenge (S256), never the verifier
	ClientKind     string
	ClientHost     string
	ClientIP       string
	VerifiedClient string // client id from ClientAuthenticator; empty if unauthenticated
	Interval       time.Duration
	CreatedAt      time.Time
	ExpiresAt      time.Time

	UserCode string // shown to the client, typed into the browser; never logged

	Protocol string // "oidc" or "saml"; set by the provider's BeginLogin, informational

	IdPState        string // broker's own OIDC state for its IdP leg
	IdPNonce        string // broker's own OIDC nonce for its IdP leg
	IdPPKCEVerifier string // broker's own PKCE verifier for its IdP leg
	SAMLRequestID   string // broker's own AuthnRequest ID, checked against the response's InResponseTo

	Identity   *Identity // set once the callback validates the ID token
	IdentityAt time.Time

	ApproveAttempts int
	CSRFToken       string

	ApprovalBindingHash string // sha256 of the approving browser's secret

	LastPollAt time.Time // enforces the poll interval (slow_down)

	State    State
	Consumed bool // true once an approved result has been handed to a poll
}

// Store persists sessions.
type Store interface {
	Create(ctx context.Context, s *Session) error
	Get(ctx context.Context, id string) (*Session, error)
	Update(ctx context.Context, s *Session) error // replaces the stored session
	Close()
}

// Memory is an in-memory Store with TTL-based eviction, safe for concurrent use.
type Memory struct {
	mu       sync.Mutex
	sessions map[string]*Session
	stopCh   chan struct{}
}

// NewMemory returns a Memory store that sweeps expired sessions until Close is called.
func NewMemory(sweep time.Duration) *Memory {
	m := &Memory{
		sessions: make(map[string]*Session),
		stopCh:   make(chan struct{}),
	}
	go m.sweepLoop(sweep)
	return m
}

func (m *Memory) sweepLoop(interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			m.sweep()
		case <-m.stopCh:
			return
		}
	}
}

// sweep evicts sessions past twice their own TTL, so a slightly delayed poll still gets an answer.
func (m *Memory) sweep() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for id, s := range m.sessions {
		if now.After(s.ExpiresAt.Add(s.ExpiresAt.Sub(s.CreatedAt))) {
			delete(m.sessions, id)
		}
	}
}

func (m *Memory) Create(_ context.Context, s *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.ID] = s
	return nil
}

func (m *Memory) Get(_ context.Context, id string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *s
	return &cp, nil
}

func (m *Memory) Update(_ context.Context, s *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sessions[s.ID]; !ok {
		return ErrNotFound
	}
	cp := *s
	m.sessions[s.ID] = &cp
	return nil
}

func (m *Memory) Close() {
	close(m.stopCh)
}
