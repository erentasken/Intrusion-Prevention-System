package mock

import (
	"context"
	"time"
)

// Mock implementation of RedisSessionStore for unit testing
type RedisSessionStoreMock struct {
	data map[string]string
}

// NewRedisSessionStoreMock initializes the mock session store
func NewRedisSessionStoreMock() *RedisSessionStoreMock {
	return &RedisSessionStoreMock{
		data: make(map[string]string),
	}
}

// Set stores a value in the mock Redis with a TTL (not used here, just for interface compatibility)
func (r *RedisSessionStoreMock) Set(ctx context.Context, key string, value string, ttl time.Duration) error {
	r.data[key] = value
	return nil
}

// Get retrieves a value from the mock Redis
func (r *RedisSessionStoreMock) Get(ctx context.Context, key string) (string, error) {
	return r.data[key], nil
}

// Exists checks if a key exists in the mock Redis
func (r *RedisSessionStoreMock) Exists(ctx context.Context, key string) (bool, error) {
	_, exists := r.data[key]
	return exists, nil
}

// Delete removes a key from the mock Redis
func (r *RedisSessionStoreMock) Delete(ctx context.Context, key string) error {
	delete(r.data, key)
	return nil
}
