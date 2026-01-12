package creator

import (
	"context"
	"database/sql"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/pressly/goose/v3"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

var testDB *sql.DB

func TestMain(m *testing.M) {
	ctx := context.Background()

	pgContainer, err := postgres.Run(
		ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("newsify_newsarticle_test"),
		postgres.WithUsername("testAdmin"),
		postgres.WithPassword("testPassword"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(5*time.Second),
		),
	)
	if err != nil {
		log.Fatalf("failed to start container: %v", err)
	}

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		log.Fatalf("failed to get connection string: %v", err)
	}

	log.Printf("connection string is %s", connStr)

	testDB, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("failed to connect to db:  %v", err)
	}

	migrationsPath := filepath.Join("..", "..", "..", "cmd", "migrate", "migrations")

	if err := goose.SetDialect("postgres"); err != nil {
		log.Fatalf("failed to set dialect: %v", err)
	}

	if err := goose.Up(testDB, migrationsPath); err != nil {
		log.Fatalf("failed to run migrations: %v", err)
	}

	code := m.Run()

	if err := pgContainer.Terminate(ctx); err != nil {
		log.Printf("failed to terminal container: %v", err)
	}

	os.Exit(code)
}
