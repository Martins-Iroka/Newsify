package config

import (
	"time"

	"com.martdev.newsify/internal/env"
)

type Configuration struct {
	Addr       string
	DB         dbConfig
	AuthConfig authConfig
}

type dbConfig struct {
	Addr                       string
	MaxOpenConns, MaxIdleConns int
	MaxIdleTime                string
}

type authConfig struct {
	Secret string
	Exp    time.Duration
	Iss    string
}

var Config = initConfig()

func initConfig() Configuration {
	return Configuration{
		Addr: env.GetString("ADDR", ":8080"),
		DB: dbConfig{
			Addr:         env.GetString("DB_ADDR", ""),
			MaxOpenConns: env.GetInt("DB_MAX_OPEN_CONNS", 30),
			MaxIdleConns: env.GetInt("DB_MAX_IDLE_CONNS", 30),
			MaxIdleTime:  env.GetString("DB_MAX_IDLE_TIME", "15m"),
		},
		AuthConfig: authConfig{
			Secret: env.GetString("AUTH_TOKEN_SECRET", "test"),
			Exp:    time.Minute * 15,
			Iss:    "Newsify",
		},
	}
}
