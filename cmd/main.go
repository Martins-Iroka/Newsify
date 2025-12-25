package main

import (
	"log"
	"net/http"
	"time"

	"com.martdev.newsify/config"
	userhandler "com.martdev.newsify/internal/api/user"
	"com.martdev.newsify/internal/auth/jwt"
	"com.martdev.newsify/internal/auth/twilio"
	"com.martdev.newsify/internal/database"
	userdatabase "com.martdev.newsify/internal/database/user"
	"com.martdev.newsify/internal/env"
	userservice "com.martdev.newsify/internal/service/user"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"go.uber.org/zap"
)

func main() {
	logger := zap.Must(zap.NewProduction()).Sugar()
	defer logger.Sync()

	db, err := database.NewPostgreInstance(
		config.Config.DB.Addr,
		config.Config.DB.MaxOpenConns,
		config.Config.DB.MaxIdleConns,
		config.Config.DB.MaxIdleTime,
	)

	if err != nil {
		logger.Fatalf("db error - %s", err)
	}
	defer db.Close()
	logger.Info("data connection pool established")

	mux := getChiMux()

	twilio := twilio.NewTwilioVerification(
		config.Config.TwilioConfig.AccountSID,
		config.Config.TwilioConfig.AuthToken,
		config.Config.TwilioConfig.ServiceID,
		logger,
	)

	jwtAuthenticator, err := jwt.NewJWTAuthenticator(
		config.Config.AuthConfig.Secret,
		config.Config.AuthConfig.Iss,
		config.Config.AuthConfig.Iss,
	)
	if err != nil {
		logger.Error(err)
	}

	userStore := userdatabase.UserStore{DB: db}
	userService := userservice.NewService(
		&userStore, jwtAuthenticator, twilio, logger, config.Config,
	)
	userHandler := userhandler.NewHandler(userService, logger)
	userHandler.RegisterRoutes(mux)

	logger.Fatal(runServer(mux))
}

func getChiMux() *chi.Mux {
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{env.GetString("CORS_ALLOWED_ORIGIN", "http://127.0.0.1:4040")},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: false,
		MaxAge:           300,
	}))
	r.Use(middleware.Timeout(60 * time.Second))

	return r
}

func runServer(mux http.Handler) error {

	srv := &http.Server{
		Addr:         config.Config.Addr,
		Handler:      mux,
		WriteTimeout: time.Second * 30,
		ReadTimeout:  time.Second * 10,
		IdleTimeout:  time.Minute,
	}

	log.Printf("server has started at %s", config.Config.Addr)

	return srv.ListenAndServe()
}
