package user

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

	// 1. Start Postgres Container
	pgContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("newsify_test"),
		postgres.WithUsername("postgres"),
		postgres.WithPassword("postgres"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(5*time.Second),
		),
	)
	if err != nil {
		log.Fatalf("failed to start container: %v", err)
	}

	// 2. Get Connection String
	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		log.Fatalf("failed to get connection string: %v", err)
	}

	// 3. Connect to DB
	// We open the connection directly to avoid import cycles with the 'database' package
	testDB, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("failed to connect to db: %v", err)
	}

	// 4. Run Migrations
	// Point to the migrations folder relative to this file
	migrationsPath := filepath.Join("..", "..", "..", "cmd", "migrate", "migrations")

	if err := goose.SetDialect("postgres"); err != nil {
		log.Fatalf("failed to set dialect: %v", err)
	}

	if err := goose.Up(testDB, migrationsPath); err != nil {
		log.Fatalf("failed to run migrations: %v", err)
	}

	// 5. Run Tests
	code := m.Run()

	// 6. Cleanup
	if err := pgContainer.Terminate(ctx); err != nil {
		log.Printf("failed to terminate container: %v", err)
	}

	os.Exit(code)
}

// setupTest cleans the database between tests
func setupTest(t *testing.T) {
	_, err := testDB.Exec("TRUNCATE TABLE users CASCADE")
	if err != nil {
		t.Fatalf("failed to truncate tables: %v", err)
	}
}

func TestUserStoreCreateUserAndVerificationToken(t *testing.T) {
	setupTest(t)

	store := &UserStore{DB: testDB}
	ctx := context.Background()

	t.Run("should create a user and verification token successfully", func(t *testing.T) {
		user := &User{
			Username: "testuser_container",
			Email:    "container@example.com",
			Password: "hashedpassword123",
		}
		token := "verification-token-container"

		err := store.CreateUserAndVerificationToken(ctx, user, token)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if user.ID == 0 {
			t.Error("expected user ID to be set")
		}

		savedUser, err := store.GetUserByID(ctx, user.ID)
		if err != nil {
			t.Fatalf("failed to get user: %v", err)
		}
		if savedUser.Email != user.Email {
			t.Errorf("expected email %s, got %s", user.Email, savedUser.Email)
		}
	})

	t.Run("should fail with duplicate email", func(t *testing.T) {
		user1 := &User{
			Username: "user1",
			Email:    "duplicate@example.com",
			Password: "pw1",
		}
		_ = store.CreateUserAndVerificationToken(ctx, user1, "token1")

		user2 := &User{
			Username: "user2",
			Email:    "duplicate@example.com",
			Password: "pw2",
		}
		err := store.CreateUserAndVerificationToken(ctx, user2, "token2")

		if err == nil {
			t.Error("expected error for duplicate email, got nil")
		}
	})
}
