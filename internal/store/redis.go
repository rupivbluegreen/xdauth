package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisConfig configures a Redis-backed Store, shared across broker replicas.
type RedisConfig struct {
	Client    *redis.Client
	KeyPrefix string // default "xdauth:session:"
}

// Redis is a shared Store; TTL eviction is Redis's own key expiry.
type Redis struct {
	client    *redis.Client
	keyPrefix string
}

// NewRedis returns a ready Redis-backed Store. The Store owns cfg.Client's
// lifecycle: Close() closes it.
func NewRedis(cfg RedisConfig) *Redis {
	prefix := cfg.KeyPrefix
	if prefix == "" {
		prefix = "xdauth:session:"
	}
	return &Redis{client: cfg.Client, keyPrefix: prefix}
}

func (s *Redis) key(id string) string { return s.keyPrefix + id }

func (s *Redis) Create(ctx context.Context, sess *Session) error {
	return s.write(ctx, sess)
}

func (s *Redis) Get(ctx context.Context, id string) (*Session, error) {
	raw, err := s.client.Get(ctx, s.key(id)).Bytes()
	if err == redis.Nil {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store/redis: get: %w", err)
	}
	var sess Session
	if err := json.Unmarshal(raw, &sess); err != nil {
		return nil, fmt.Errorf("store/redis: decode: %w", err)
	}
	return &sess, nil
}

// Update requires the key to already exist, matching Memory's semantics.
func (s *Redis) Update(ctx context.Context, sess *Session) error {
	n, err := s.client.Exists(ctx, s.key(sess.ID)).Result()
	if err != nil {
		return fmt.Errorf("store/redis: exists: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return s.write(ctx, sess)
}

// write sets the key with a TTL past ExpiresAt, matching Memory.sweep's
// 2x-TTL grace window so a slightly delayed poll still gets an answer.
func (s *Redis) write(ctx context.Context, sess *Session) error {
	raw, err := json.Marshal(sess)
	if err != nil {
		return fmt.Errorf("store/redis: encode: %w", err)
	}
	ttl := time.Until(sess.ExpiresAt.Add(sess.ExpiresAt.Sub(sess.CreatedAt)))
	if ttl <= 0 {
		ttl = time.Minute
	}
	if err := s.client.Set(ctx, s.key(sess.ID), raw, ttl).Err(); err != nil {
		return fmt.Errorf("store/redis: set: %w", err)
	}
	return nil
}

func (s *Redis) Close() {
	_ = s.client.Close()
}
