// Package broker implements the xdauth session state machine and its four phishing-resistance checks.
package broker

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rupivbluegreen/xdauth/internal/store"
)

// Errors returned by the state machine; handlers map these to HTTP responses.
var (
	ErrExpired          = errors.New("session expired")
	ErrConsumed         = errors.New("session already consumed")
	ErrWrongState       = errors.New("session is not in a state that allows this operation")
	ErrInvalidVerifier  = errors.New("code_verifier does not match code_challenge")
	ErrIdentityMismatch = errors.New("authenticated identity does not match login_hint")
)

// Normalizer maps an identity claim value into a form comparable against login_hint.
type Normalizer func(s string) string

func defaultNormalizer(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func newSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate session id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func newCSRFToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate csrf token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// StartParams is what /auth/start needs to create a session.
type StartParams struct {
	LoginHint     string
	CodeChallenge string
	ClientKind    string
	ClientHost    string
	ClientIP      string
}

// newSession creates a Pending session; ttl and interval come from broker config, never the client.
func newSession(p StartParams, ttl, interval time.Duration) (*store.Session, error) {
	id, err := newSessionID()
	if err != nil {
		return nil, err
	}
	code, err := GenerateUserCode()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	return &store.Session{
		ID:            id,
		LoginHint:     p.LoginHint,
		CodeChallenge: p.CodeChallenge,
		ClientKind:    p.ClientKind,
		ClientHost:    p.ClientHost,
		ClientIP:      p.ClientIP,
		Interval:      interval,
		CreatedAt:     now,
		ExpiresAt:     now.Add(ttl),
		UserCode:      code,
		State:         store.StatePending,
	}, nil
}

// isExpired reports whether s's TTL has elapsed, without mutating s.
func isExpired(s *store.Session, now time.Time) bool {
	return now.After(s.ExpiresAt)
}

// expireIfNeeded moves s to StateExpired if its TTL elapsed and it isn't already terminal.
func expireIfNeeded(s *store.Session, now time.Time) bool {
	if s.State == store.StateExpired {
		return true
	}
	if isTerminal(s.State) {
		return false
	}
	if isExpired(s, now) {
		s.State = store.StateExpired
		return true
	}
	return false
}

func isTerminal(st store.State) bool {
	switch st {
	case store.StateApproved, store.StateDenied, store.StateExpired:
		return true
	default:
		return false
	}
}

// bindIdentity attaches the verified IdP identity and enforces check 4 (identity match) immediately.
func bindIdentity(s *store.Session, ident store.Identity, normalize Normalizer, now time.Time) error {
	if expireIfNeeded(s, now) {
		return ErrExpired
	}
	if s.State != store.StatePending {
		return ErrWrongState
	}
	if normalize == nil {
		normalize = defaultNormalizer
	}
	s.Identity = &ident
	s.IdentityAt = now

	if normalize(ident.Value) != normalize(s.LoginHint) {
		s.State = store.StateDenied
		return ErrIdentityMismatch
	}

	token, err := newCSRFToken()
	if err != nil {
		return err
	}
	s.CSRFToken = token
	s.State = store.StateAwaitingApproval
	return nil
}

const maxApproveAttempts = 5

// approve implements check 2 (number matching); an explicit deny always denies regardless of the code.
func approve(s *store.Session, submittedCode string, decisionApprove bool, now time.Time) error {
	if expireIfNeeded(s, now) {
		return ErrExpired
	}
	if s.State != store.StateAwaitingApproval {
		return ErrWrongState
	}
	if !decisionApprove {
		s.State = store.StateDenied
		return nil
	}
	if codesEqual(submittedCode, s.UserCode) {
		s.State = store.StateApproved
		return nil
	}
	s.ApproveAttempts++
	if s.ApproveAttempts >= maxApproveAttempts {
		s.State = store.StateDenied
		return errors.New("too many incorrect codes")
	}
	return errors.New("incorrect code")
}

// PollStatus is the outcome POST /auth/poll reports to the client.
type PollStatus string

const (
	PollPending  PollStatus = "pending"
	PollApproved PollStatus = "approved"
	PollDenied   PollStatus = "denied"
	PollExpired  PollStatus = "expired"
	PollSlowDown PollStatus = "slow_down"
)

// Artifact is what a successful poll releases.
type Artifact struct {
	Subject    string
	Identity   string
	Claims     map[string]any
	ApprovedAt time.Time
}

// PollResult is the full outcome of poll.
type PollResult struct {
	Status   PollStatus
	Artifact *Artifact
}

// poll implements check 1 (PKCE) and single-use consumption of the approved artifact.
func poll(s *store.Session, codeVerifier string, now time.Time) (PollResult, error) {
	if expireIfNeeded(s, now) {
		return PollResult{Status: PollExpired}, nil
	}

	if s.State == store.StateApproved {
		if s.Consumed {
			return PollResult{Status: PollExpired}, nil
		}
		if !verifyClientPKCE(codeVerifier, s.CodeChallenge) {
			return PollResult{}, ErrInvalidVerifier // phishing scenario (a): attacker lacks the verifier
		}
		s.Consumed = true
		return PollResult{Status: PollApproved, Artifact: &Artifact{
			Subject:    s.Identity.Subject,
			Identity:   s.Identity.Value,
			Claims:     s.Identity.Claims,
			ApprovedAt: s.IdentityAt,
		}}, nil
	}

	if !verifyClientPKCE(codeVerifier, s.CodeChallenge) {
		return PollResult{}, ErrInvalidVerifier
	}

	if !s.LastPollAt.IsZero() && now.Sub(s.LastPollAt) < s.Interval {
		return PollResult{Status: PollSlowDown}, nil
	}
	s.LastPollAt = now

	switch s.State {
	case store.StateDenied:
		return PollResult{Status: PollDenied}, nil
	case store.StateExpired:
		return PollResult{Status: PollExpired}, nil
	default: // Pending, AwaitingApproval
		return PollResult{Status: PollPending}, nil
	}
}
