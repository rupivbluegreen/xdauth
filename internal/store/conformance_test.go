package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runStoreConformance exercises the Store contract against any implementation.
func runStoreConformance(t *testing.T, newStore func() Store) {
	t.Run("CreateThenGet", func(t *testing.T) {
		st := newStore()
		defer st.Close()
		ctx := context.Background()
		sess := &Session{ID: "s1", LoginHint: "alice", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour), State: StatePending}
		require.NoError(t, st.Create(ctx, sess))

		got, err := st.Get(ctx, "s1")
		require.NoError(t, err)
		assert.Equal(t, "alice", got.LoginHint)
		assert.Equal(t, StatePending, got.State)
	})

	t.Run("GetMissingReturnsErrNotFound", func(t *testing.T) {
		st := newStore()
		defer st.Close()
		_, err := st.Get(context.Background(), "nope")
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("UpdatePersistsMutation", func(t *testing.T) {
		st := newStore()
		defer st.Close()
		ctx := context.Background()
		sess := &Session{ID: "s2", State: StatePending, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
		require.NoError(t, st.Create(ctx, sess))

		sess.State = StateApproved
		require.NoError(t, st.Update(ctx, sess))

		got, err := st.Get(ctx, "s2")
		require.NoError(t, err)
		assert.Equal(t, StateApproved, got.State)
	})

	t.Run("UpdateMissingReturnsErrNotFound", func(t *testing.T) {
		st := newStore()
		defer st.Close()
		err := st.Update(context.Background(), &Session{ID: "ghost", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("GetReturnsIndependentCopy", func(t *testing.T) {
		st := newStore()
		defer st.Close()
		ctx := context.Background()
		sess := &Session{ID: "s3", LoginHint: "alice", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
		require.NoError(t, st.Create(ctx, sess))

		got1, err := st.Get(ctx, "s3")
		require.NoError(t, err)
		got1.LoginHint = "mutated"

		got2, err := st.Get(ctx, "s3")
		require.NoError(t, err)
		assert.Equal(t, "alice", got2.LoginHint, "mutating one Get result must not affect another")
	})

	t.Run("RoundTripsFullSessionShape", func(t *testing.T) {
		st := newStore()
		defer st.Close()
		ctx := context.Background()
		now := time.Now().Truncate(time.Second)
		sess := &Session{
			ID: "s4", LoginHint: "alice", CodeChallenge: "chal", ClientKind: "cli",
			ClientHost: "host-1", ClientIP: "10.0.0.1", VerifiedClient: "bastion-01",
			Interval: 3 * time.Second, CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute),
			UserCode: "ABCD-1234", Protocol: "oidc",
			Identity:   &Identity{Subject: "sub-1", Value: "alice", Claims: map[string]any{"k": "v"}},
			IdentityAt: now, ApproveAttempts: 1, CSRFToken: "csrf", ApprovalBindingHash: "hash",
			LastPollAt: now, State: StateAwaitingApproval, Consumed: false,
		}
		require.NoError(t, st.Create(ctx, sess))

		got, err := st.Get(ctx, "s4")
		require.NoError(t, err)
		assert.Equal(t, sess.LoginHint, got.LoginHint)
		assert.Equal(t, sess.VerifiedClient, got.VerifiedClient)
		assert.Equal(t, sess.ApprovalBindingHash, got.ApprovalBindingHash)
		require.NotNil(t, got.Identity)
		assert.Equal(t, "alice", got.Identity.Value)
		assert.Equal(t, "v", got.Identity.Claims["k"])
	})
}

func TestMemory_Conformance(t *testing.T) {
	runStoreConformance(t, func() Store { return NewMemory(time.Hour) })
}
