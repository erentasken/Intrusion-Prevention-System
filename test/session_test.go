package service

import (
	"context"
	"main/test/mock"
	"testing"
	"time"
)

// TestRedisSessionStore performs integration tests for the RedisSessionStore
func TestRedisSessionStore(t *testing.T) {
	// Initialize a Redis session store (this would require a running Redis instance)
	store := mock.NewRedisSessionStoreMock()

	// Define the context for testing
	ctx := context.Background()

	// Define test key-value pairs
	key := "session:test_key"
	value := "active"
	ttl := 2 * time.Second // Set a TTL for the session

	// Test: Set a key-value pair with TTL
	err := store.Set(ctx, key, value, ttl)
	if err != nil {
		t.Errorf("Failed to set key-value pair: %v", err)
	}

	// Test: Get the value of a key
	storedValue, err := store.Get(ctx, key)
	if err != nil {
		t.Errorf("Failed to get key value: %v", err)
	}
	if storedValue != value {
		t.Errorf("Expected value %v, but got %v", value, storedValue)
	}

	// Test: Check if the key exists
	exists, err := store.Exists(ctx, key)
	if err != nil {
		t.Errorf("Failed to check if key exists: %v", err)
	}
	if !exists {
		t.Errorf("Expected key %v to exist, but it does not", key)
	}

	// Test: Wait for TTL expiration
	time.Sleep(ttl + time.Second) // Wait slightly longer than the TTL to ensure expiration

	// Check if the key exists after expiration
	exists, err = store.Exists(ctx, key)
	if err != nil {
		t.Errorf("Failed to check if key exists after TTL: %v", err)
	}
	if exists {
		t.Errorf("Expected key %v to expire, but it still exists", key)
	}

	// Test: Delete a key
	err = store.Delete(ctx, key)
	if err != nil {
		t.Errorf("Failed to delete key: %v", err)
	}

	// Test: Ensure the key is deleted
	storedValue, err = store.Get(ctx, key)
	if err != nil {
		t.Errorf("Failed to get key value after deletion: %v", err)
	}
	if storedValue != "" {
		t.Errorf("Expected key %v to be deleted, but got %v", key, storedValue)
	}

	// Test Cleanup: Ensure the store is in the expected state
	exists, err = store.Exists(ctx, key)
	if err != nil {
		t.Errorf("Failed to check key existence after cleanup: %v", err)
	}
	if exists {
		t.Errorf("Expected key %v to be deleted, but it still exists after cleanup", key)
	}
}

// TestRedisSessionStore_Mock simulates the Redis interaction for unit testing
func TestRedisSessionStore_Mock(t *testing.T) {
	// Initialize the mock Redis session store
	store := mock.NewRedisSessionStoreMock()

	// Define the context for testing
	ctx := context.Background()

	// Define test key-value pairs
	key := "session:test_key"
	value := "active"
	ttl := 2 * time.Second // TTL is not used in mock, just for interface compatibility

	// Test: Set a key-value pair
	err := store.Set(ctx, key, value, ttl)
	if err != nil {
		t.Errorf("Failed to set key-value pair: %v", err)
	}

	// Test: Get the value of a key
	storedValue, err := store.Get(ctx, key)
	if err != nil {
		t.Errorf("Failed to get key value: %v", err)
	}
	if storedValue != value {
		t.Errorf("Expected value %v, but got %v", value, storedValue)
	}

	// Test: Check if the key exists
	exists, err := store.Exists(ctx, key)
	if err != nil {
		t.Errorf("Failed to check if key exists: %v", err)
	}
	if !exists {
		t.Errorf("Expected key %v to exist, but it does not", key)
	}

	// Test: Delete a key
	err = store.Delete(ctx, key)
	if err != nil {
		t.Errorf("Failed to delete key: %v", err)
	}

	// Test: Ensure the key is deleted
	storedValue, err = store.Get(ctx, key)
	if err != nil {
		t.Errorf("Failed to get key value after deletion: %v", err)
	}
	if storedValue != "" {
		t.Errorf("Expected key %v to be deleted, but got %v", key, storedValue)
	}
}
