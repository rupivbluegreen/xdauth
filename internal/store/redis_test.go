package store

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func newMiniredisStore(t *testing.T) Store {
	t.Helper()
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	return NewRedis(RedisConfig{Client: client})
}

func TestRedis_Conformance(t *testing.T) {
	runStoreConformance(t, func() Store { return newMiniredisStore(t) })
}

// TestRedis_SharedAcrossTwoHandles: the whole point of a shared store.
func TestRedis_SharedAcrossTwoHandles(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	client1 := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	client2 := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	replica1 := NewRedis(RedisConfig{Client: client1})
	replica2 := NewRedis(RedisConfig{Client: client2})

	now := time.Now()
	sess := &Session{ID: "shared-1", LoginHint: "alice", CreatedAt: now, ExpiresAt: now.Add(time.Hour), State: StatePending}
	require.NoError(t, replica1.Create(t.Context(), sess))

	got, err := replica2.Get(t.Context(), "shared-1")
	require.NoError(t, err)
	require.Equal(t, "alice", got.LoginHint, "a session created on one replica must be visible on another")

	got.State = StateApproved
	require.NoError(t, replica2.Update(t.Context(), got))

	got2, err := replica1.Get(t.Context(), "shared-1")
	require.NoError(t, err)
	require.Equal(t, StateApproved, got2.State, "an update on one replica must be visible on another")
}
