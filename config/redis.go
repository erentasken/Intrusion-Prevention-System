package config

import (
	"fmt"
	"log"

	"github.com/redis/go-redis/v9"
	"golang.org/x/net/context"
)

type RedisOrigin struct {
	Client  *redis.Client
	context context.Context
}

// InitializeRedis initializes the Redis client
func InitializeRedis() *RedisOrigin {
	redisOrigin := &RedisOrigin{
		Client: redis.NewClient(&redis.Options{
			Addr: "cache:6379", // Replace with your Redis address
		}),
		context: context.Background(),
	}

	_, err := redisOrigin.Client.Ping(redisOrigin.context).Result()
	if err != nil {
		log.Fatalf("Could not connect to Redis: %v", err)
	} else {
		fmt.Println("Connected to Redis successfully.")
	}

	return redisOrigin
}

// redisWrapper struct to hold the Redis client
type redisWrapper struct {
	redisOrigin RedisOrigin
}

// RedisWrapper interface defines the methods available for interacting with Redis
type RedisWrapper interface {
	SetKey(ctx context.Context, key string, value string) error
	GetKey(ctx context.Context, key string) (string, error)
}

// NewRedisWrapper initializes and returns a RedisWrapper interface
func NewRedisWrapper(redisOrigin RedisOrigin) RedisWrapper {
	return &redisWrapper{redisOrigin: redisOrigin}
}

// SetKey sets a key-value pair in Redis
func (r *redisWrapper) SetKey(ctx context.Context, key string, value string) error {
	err := r.redisOrigin.Client.Set(ctx, key, value, 0).Err()
	if err != nil {
		log.Printf("Error setting key %s: %v", key, err)
		return err
	}
	fmt.Printf("Successfully set key: %s\n", key)
	return nil
}

// GetKey retrieves the value of a key from Redis
func (r *redisWrapper) GetKey(ctx context.Context, key string) (string, error) {
	val, err := r.redisOrigin.Client.Get(ctx, key).Result()
	if err == redis.Nil {
		fmt.Printf("Key %s does not exist\n", key)
		return "", nil
	} else if err != nil {
		log.Printf("Error getting key %s: %v", key, err)
		return "", err
	}
	return val, nil
}
