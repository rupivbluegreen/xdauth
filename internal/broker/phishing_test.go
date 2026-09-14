// This file is the project's proof: an attacker-initiated session must never be completable by a victim.
package broker

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/rupivbluegreen/xdauth/internal/store"
)

// TestPhishing_LegitimatePathSucceeds is the control case: the same actor starts, approves, and polls.
func TestPhishing_LegitimatePathSucceeds(t *testing.T) {
	p, verifier := testParams(t, "attacker-verifier")
	s, err := newSession(p, 5*time.Minute, 0)
	require.NoError(t, err)

	require.NoError(t, bindIdentity(s, store.Identity{Subject: "sub-alice", Value: "alice"}, nil, time.Now(), hashBinding("b")))
	require.NoError(t, approve(s, s.UserCode, true, time.Now(), "b"))

	res, err := poll(s, verifier, time.Now())
	require.NoError(t, err)
	assert.Equal(t, PollApproved, res.Status)
	require.NotNil(t, res.Artifact)
	assert.Equal(t, "alice", res.Artifact.Identity)
}

// TestPhishing_AttackerLacksVerifier: the attacker started the session but polls without its verifier.
func TestPhishing_AttackerLacksVerifier(t *testing.T) {
	p, _ := testParams(t, "attacker-verifier")
	s, err := newSession(p, 5*time.Minute, 0)
	require.NoError(t, err)

	require.NoError(t, bindIdentity(s, store.Identity{Value: "alice"}, nil, time.Now(), hashBinding("b")))
	require.NoError(t, approve(s, s.UserCode, true, time.Now(), "b"))

	_, err = poll(s, "not-the-real-verifier", time.Now())
	require.ErrorIs(t, err, ErrInvalidVerifier, "poll with the wrong verifier must never approve")
}

// TestPhishing_VictimEntersNoCode: the victim opens the link but never approves.
func TestPhishing_VictimEntersNoCode(t *testing.T) {
	p, verifier := testParams(t, "attacker-verifier")
	s, err := newSession(p, 5*time.Minute, 0)
	require.NoError(t, err)

	require.NoError(t, bindIdentity(s, store.Identity{Value: "alice"}, nil, time.Now(), hashBinding("b")))

	res, err := poll(s, verifier, time.Now())
	require.NoError(t, err)
	assert.Equal(t, PollPending, res.Status, "no approval means the attacker's poll must stay pending, never approved")
}

// TestPhishing_VictimEntersWrongCode: the victim mistypes or refuses the code.
func TestPhishing_VictimEntersWrongCode(t *testing.T) {
	p, verifier := testParams(t, "attacker-verifier")
	s, err := newSession(p, 5*time.Minute, 0)
	require.NoError(t, err)

	require.NoError(t, bindIdentity(s, store.Identity{Value: "alice"}, nil, time.Now(), hashBinding("b")))
	require.Error(t, approve(s, "0000-0000", true, time.Now(), "b"))

	res, err := poll(s, verifier, time.Now())
	require.NoError(t, err)
	assert.NotEqual(t, PollApproved, res.Status, "a wrong code must never approve the attacker's session")
}

// TestPhishing_VictimIdentityDiffersFromLoginHint: attacker starts for "alice", the IdP login completes as "mallory".
func TestPhishing_VictimIdentityDiffersFromLoginHint(t *testing.T) {
	p, verifier := testParams(t, "attacker-verifier")
	p.LoginHint = "alice"
	s, err := newSession(p, 5*time.Minute, 0)
	require.NoError(t, err)

	bindErr := bindIdentity(s, store.Identity{Subject: "sub-mallory", Value: "mallory"}, nil, time.Now(), hashBinding("b"))
	require.ErrorIs(t, bindErr, ErrIdentityMismatch)
	require.Equal(t, store.StateDenied, s.State, "identity mismatch must deny, not merely skip approval")

	approveErr := approve(s, s.UserCode, true, time.Now(), "b")
	require.ErrorIs(t, approveErr, ErrWrongState, "a denied session cannot be approved afterwards")

	res, err := poll(s, verifier, time.Now())
	require.NoError(t, err)
	assert.Equal(t, PollDenied, res.Status)
}

// TestPhishing_ApprovalRequiresAuthenticatedBrowsersBinding: wrong binding secret never approves.
func TestPhishing_ApprovalRequiresAuthenticatedBrowsersBinding(t *testing.T) {
	p, verifier := testParams(t, "attacker-verifier")
	s, err := newSession(p, 5*time.Minute, 0)
	require.NoError(t, err)

	require.NoError(t, bindIdentity(s, store.Identity{Value: "alice"}, nil, time.Now(), hashBinding("victim-secret")))

	approveErr := approve(s, s.UserCode, true, time.Now(), "attacker-guess")
	require.ErrorIs(t, approveErr, ErrApprovalNotBound)
	assert.Equal(t, store.StateAwaitingApproval, s.State, "wrong binding must not move state at all")

	res, err := poll(s, verifier, time.Now())
	require.NoError(t, err)
	assert.Equal(t, PollPending, res.Status)

	require.NoError(t, approve(s, s.UserCode, true, time.Now(), "victim-secret"))
	res, err = poll(s, verifier, time.Now())
	require.NoError(t, err)
	assert.Equal(t, PollApproved, res.Status, "the correctly-bound browser can still approve")
}

// TestPhishing_ExpiredSessionNeverApproves: the attacker waits past the TTL before polling.
func TestPhishing_ExpiredSessionNeverApproves(t *testing.T) {
	p, verifier := testParams(t, "attacker-verifier")
	s, err := newSession(p, time.Millisecond, 0)
	require.NoError(t, err)

	res, err := poll(s, verifier, time.Now().Add(time.Second))
	require.NoError(t, err)
	assert.Equal(t, PollExpired, res.Status)
}

// TestPhishing_ReplayedSessionNeverApprovesTwice: a session must not release its artifact twice.
func TestPhishing_ReplayedSessionNeverApprovesTwice(t *testing.T) {
	p, verifier := testParams(t, "attacker-verifier")
	s, err := newSession(p, 5*time.Minute, 0)
	require.NoError(t, err)

	require.NoError(t, bindIdentity(s, store.Identity{Value: "alice"}, nil, time.Now(), hashBinding("b")))
	require.NoError(t, approve(s, s.UserCode, true, time.Now(), "b"))

	first, err := poll(s, verifier, time.Now())
	require.NoError(t, err)
	require.Equal(t, PollApproved, first.Status)

	second, err := poll(s, verifier, time.Now())
	require.NoError(t, err)
	assert.Equal(t, PollExpired, second.Status, "a replayed poll must never return approved twice")
}
