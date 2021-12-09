package redisclient

import (
	"os"

	"github.com/go-redis/redis"
)

// The Redis client is initialized in the init() function.
// This ensures that each time we run the main.go file, Redis is automatically connected.
var Client *redis.Client

func init() {

	//Initializing redis
	dsn := os.Getenv("REDIS_DSN")
	if len(dsn) == 0 {
		dsn = "localhost:6379"
	}
	Client = redis.NewClient(&redis.Options{
		Addr: dsn, //redis port
	})
	_, err := Client.Ping().Result()
	if err != nil {
		panic(err)
	}

}
