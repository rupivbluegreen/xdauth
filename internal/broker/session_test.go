package broker

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rupivbluegreen/xdauth/internal/store"
)

func testParams(t *testing.T, verifier string) (StartParams, string) {
	t.Helper()
	return StartParams{
		LoginHint:     "alice",
		CodeChallenge: challengeFor(verifier),
		ClientKind:    "cli",
		ClientHost:    "host-42",
		ClientIP:      "10.1.2.3",
	}, verifier
}

// challengeFor computes the S256 code_challenge for a test verifier.
func challengeFor(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestNewSession(t *testing.T) {
	p, _ := testParams(t, "verifier-1")
	now := time.Now()
	s, err := newSession(p, 5*time.Minute, 3*time.Second)
	require.NoError(t, err)
	assert.Equal(t, store.StatePending, s.State)
	assert.Equal(t, p.LoginHint, s.LoginHint)
	assert.NotEmpty(t, s.ID)
	assert.NotEmpty(t, s.UserCode)
	assert.WithinDuration(t, now.Add(5*time.Minute), s.ExpiresAt, 2*time.Second)
}

func TestBindIdentity_MatchTransitionsToAwaitingApproval(t *testing.T) {
	p, _ := testParams(t, "verifier-1")
	s, _ := newSession(p, 5*time.Minute, 3*time.Second)

	err := bindIdentity(s, store.Identity{Subject: "sub-1", Value: "alice"}, nil, time.Now(), hashBinding("b"))
	require.NoError(t, err)
	assert.Equal(t, store.StateAwaitingApproval, s.State)
	assert.NotEmpty(t, s.CSRFToken)
}

func TestBindIdentity_MismatchDeniesImmediately(t *testing.T) {
	p, _ := testParams(t, "verifier-1")
	s, _ := newSession(p, 5*time.Minute, 3*time.Second)

	err := bindIdentity(s, store.Identity{Subject: "sub-2", Value: "mallory"}, nil, time.Now(), hashBinding("b"))
	require.ErrorIs(t, err, ErrIdentityMismatch)
	assert.Equal(t, store.StateDenied, s.State)
}

func TestBindIdentity_CaseInsensitiveByDefault(t *testing.T) {
	p, _ := testParams(t, "verifier-1")
	p.LoginHint = "Alice@Example.com"
	s, _ := newSession(p, 5*time.Minute, 3*time.Second)

	err := bindIdentity(s, store.Identity{Subject: "sub-1", Value: "alice@example.com"}, nil, time.Now(), hashBinding("b"))
	require.NoError(t, err)
	assert.Equal(t, store.StateAwaitingApproval, s.State)
}

func TestApprove_WrongCodeThenCorrect(t *testing.T) {
	p, _ := testParams(t, "verifier-1")
	s, _ := newSession(p, 5*time.Minute, 3*time.Second)
	require.NoError(t, bindIdentity(s, store.Identity{Value: "alice"}, nil, time.Now(), hashBinding("b")))

	err := approve(s, "WRONG-CODE", true, time.Now(), "b")
	require.Error(t, err)
	assert.Equal(t, store.StateAwaitingApproval, s.State)
	assert.Equal(t, 1, s.ApproveAttempts)

	err = approve(s, s.UserCode, true, time.Now(), "b")
	require.NoError(t, err)
	assert.Equal(t, store.StateApproved, s.State)
}

func TestApprove_TooManyWrongCodesDenies(t *testing.T) {
	p, _ := testParams(t, "verifier-1")
	s, _ := newSession(p, 5*time.Minute, 3*time.Second)
	require.NoError(t, bindIdentity(s, store.Identity{Value: "alice"}, nil, time.Now(), hashBinding("b")))

	for i := 0; i < maxApproveAttempts; i++ {
		_ = approve(s, "WRONG-CODE", true, time.Now(), "b")
	}
	assert.Equal(t, store.StateDenied, s.State)

	err := approve(s, s.UserCode, true, time.Now(), "b")
	require.ErrorIs(t, err, ErrWrongState)
}

func TestApprove_ExplicitDenyIgnoresCode(t *testing.T) {
	p, _ := testParams(t, "verifier-1")
	s, _ := newSession(p, 5*time.Minute, 3*time.Second)
	require.NoError(t, bindIdentity(s, store.Identity{Value: "alice"}, nil, time.Now(), hashBinding("b")))

	err := approve(s, s.UserCode, false, time.Now(), "b")
	require.NoError(t, err)
	assert.Equal(t, store.StateDenied, s.State)
}

func TestPoll_PendingThenSlowDown(t *testing.T) {
	p, verifier := testParams(t, "verifier-1")
	s, _ := newSession(p, 5*time.Minute, 1*time.Minute)

	now := time.Now()
	res, err := poll(s, verifier, now)
	require.NoError(t, err)
	assert.Equal(t, PollPending, res.Status)

	res, err = poll(s, verifier, now.Add(time.Second))
	require.NoError(t, err)
	assert.Equal(t, PollSlowDown, res.Status)
}

func TestPoll_ApprovedIsSingleUse(t *testing.T) {
	p, verifier := testParams(t, "verifier-1")
	s, _ := newSession(p, 5*time.Minute, 0)
	require.NoError(t, bindIdentity(s, store.Identity{Value: "alice"}, nil, time.Now(), hashBinding("b")))
	require.NoError(t, approve(s, s.UserCode, true, time.Now(), "b"))

	res, err := poll(s, verifier, time.Now())
	require.NoError(t, err)
	require.Equal(t, PollApproved, res.Status)
	require.NotNil(t, res.Artifact)

	res, err = poll(s, verifier, time.Now())
	require.NoError(t, err)
	assert.Equal(t, PollExpired, res.Status, "a second poll after approval must never return approved again")
}

func TestPoll_ExpiredByTTL(t *testing.T) {
	p, verifier := testParams(t, "verifier-1")
	s, _ := newSession(p, time.Millisecond, 0)

	res, err := poll(s, verifier, time.Now().Add(time.Second))
	require.NoError(t, err)
	assert.Equal(t, PollExpired, res.Status)
}
