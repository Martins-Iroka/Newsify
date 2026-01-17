package main

import (
	"log"
	"net/http"
	"time"

	"com.martdev.newsify/config"
	"com.martdev.newsify/docs"
	_ "com.martdev.newsify/docs"
	userhandler "com.martdev.newsify/internal/api/user"
	"com.martdev.newsify/internal/auth/jwt"
	"com.martdev.newsify/internal/auth/stytch"
	"com.martdev.newsify/internal/database"
	userdatabase "com.martdev.newsify/internal/database/user"
	"com.martdev.newsify/internal/env"
	userservice "com.martdev.newsify/internal/service/user"
	"com.martdev.newsify/internal/util"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	httpSwagger "github.com/swaggo/http-swagger/v2"
	"go.uber.org/zap"
)

// @title						Newsify API
// @description				API for Newsify. An application for users to get latest news on a variety of topics.
// @termsOfService				http://swagger.io/terms/
//
// @contact.name				API Support
// @contact.url				http://www.swagger.io/support
// @contact.email				support@swagger.io
//
// @licence.name				Apache 2.0
// @licence.url				http://www.apache.org/licenses/LICENSE-2.0.html
//
// @host						localhost
// @BasePath					/v1
//
// @securityDefinitions.apikey	ApiKeyAuth
// @in							header
// @name						Authorization
// @description
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

	stytch, err := stytch.NewStytchVerification(
		config.Config.StytchConfig.ProjectID,
		config.Config.StytchConfig.Secret,
		logger,
	)
	if err != nil {
		logger.Errorf("error from stytch %v", err)
	}

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
		&userStore, jwtAuthenticator, stytch, logger, config.Config,
	)
	userHandler := userhandler.NewHandler(userService, logger)
	mux.Route("/v1", func(r chi.Router) {
		r.Get("/health", healthCheckHandler)
		docsURL := "/v1/swagger/doc.json"
		r.Get("/swagger/*", httpSwagger.Handler(httpSwagger.URL(docsURL)))
		userHandler.RegisterRoutes(r)
	})

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

	docs.SwaggerInfo.Host = "localhost:3000"
	docs.SwaggerInfo.BasePath = "/v1"
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

// healthcheckHandler godoc
//
//	@Summary		Healthcheck
//	@Description	Healthcheck endpoint
//	@Tags			ops
//	@Produce		json
//	@Success		200	{object}	string	"ok"
//	@Router			/health [get]
func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	data := map[string]string{
		"status": "ok",
	}

	if err := util.JSONResponse(w, http.StatusOK, data); err != nil {
		util.InternalServerErrorResponse(w, r, err, nil)
	}
}
