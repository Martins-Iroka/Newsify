package user

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
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
		postgres.WithDatabase("newsify_user_test"),
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
		setupTest(t)
		user := &User{
			Username: "testuser_container",
			Email:    "container2@example.com",
			Password: "hashedpassword123",
		}
		token := "verification-token-container"

		err := store.CreateUserAndVerificationToken(ctx, user, token)
		assert.NoError(t, err)

		assert.NotEqual(t, 0, user.ID)

		savedUser, err := store.GetUserByID(ctx, user.ID)
		assert.Nil(t, err)
		assert.Equal(t, user.Email, savedUser.Email)
	})

	t.Run("should fail with duplicate email", func(t *testing.T) {
		setupTest(t)
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
		assert.NotNil(t, err)
	})

	t.Run("should create a user and verify that token was saved", func(t *testing.T) {
		setupTest(t)
		user := &User{
			Username: "testuser_container2",
			Email:    "container@example.com",
			Password: "hashedpassword123",
		}
		token := "verification-token-test"

		err := store.CreateUserAndVerificationToken(ctx, user, token)
		assert.Nil(t, err)

		assert.NotEqual(t, 0, user.ID)

		var savedToken string
		err = testDB.QueryRow(
			"SELECT token FROM users_verification_tracking WHERE user_id = $1",
			user.ID,
		).Scan(&savedToken)

		assert.Nil(t, err)
		hash := sha256.Sum256([]byte(token))
		hashToken := hex.EncodeToString(hash[:])

		assert.Equal(t, savedToken, hashToken)
	})

	t.Run("should rollback user creation on duplicate token", func(t *testing.T) {
		setupTest(t)
		user := &User{
			Username: "user1",
			Email:    "user1@test.com",
			Password: "pass",
		}
		token := "duplicate-token"

		err := store.CreateUserAndVerificationToken(ctx, user, token)
		if err != nil {
			t.Fatalf("failed to create first user: %v", err)
		}

		user2 := &User{
			Username: "user2",
			Email:    "user2@test.com",
			Password: "pass",
		}

		err = store.CreateUserAndVerificationToken(ctx, user2, token)

		if err == nil {
			t.Fatal("expected error for duplicate token, got nil")
		}

		_, err = store.GetUserByID(ctx, user2.ID)
		if err == nil {
			t.Error("get user by id should have returned an error")
		}

		savedUser, err := store.GetUserByID(ctx, user.ID)
		if err != nil {
			t.Fatalf("expected user1 to still exist, but got error: %v", err)
		}

		if savedUser.Email != user.Email {
			t.Errorf("expected email %s, got %s", user.Email, savedUser.Email)
		}
	})
}

// func TestGetUserByEmail(t *testing.T) {
// 	setupTest(t)
// 	store := &UserStore{DB: testDB}

// 	user := &User{
// 		Username: "martdev",
// 		Email:    "martdev@test.com",
// 		Password: "martPass",
// 		Role:     "reader",
// 	}
// 	query := `INSERT INTO users (email, username, password, role) VALUES ($1, $2, $3, $4)`
// 	_, err := testDB.ExecContext(t.Context(), query, user.Email, user.Username, user.Password, user.Role)
// 	require.NoError(t, err)

// 	_, err = store.GetUserByEmail(t.Context(), user.Email)
// 	assert.Error(t, err)
// }

func TestUserStoreCreateRefreshTokenAndGetUserByRefreshToken(t *testing.T) {
	setupTest(t)

	store := &UserStore{DB: testDB}
	ctx := context.Background()
	t.Run("should create refresh token", func(t *testing.T) {
		setupTest(t)
		user := &User{
			Username: "username",
			Email:    "test@t.com",
			Password: "pass",
		}

		refreshToken := "new-refresh-token"

		err := store.CreateUserAndVerificationToken(ctx, user, "token")
		assert.Nil(t, err)
		err = store.CreateRefreshToken(ctx, user.ID, refreshToken, time.Now().Add(time.Hour))
		assert.Nil(t, err)

		var savedToken string

		err = testDB.QueryRow(
			"SELECT token_hash FROM refresh_tokens WHERE user_id = $1",
			user.ID,
		).Scan(&savedToken)

		assert.Nil(t, err)

		assert.Equal(t, refreshToken, savedToken)

		u, err := store.GetUserByRefreshToken(ctx, refreshToken)

		assert.Nil(t, err)

		assert.Equal(t, user.ID, u.ID)
	})
}

func TestUserStoreDeleteExpiredRefreshTokens(t *testing.T) {

	store := &UserStore{DB: testDB}
	ctx := context.Background()

	t.Run("delete expired refresh tokens", func(t *testing.T) {
		setupTest(t)
		user := &User{
			Username: "username",
			Email:    "test@t.com",
			Password: "pass",
		}

		err := store.CreateUserAndVerificationToken(ctx, user, "verification-token")
		assert.Nil(t, err)

		err = store.CreateRefreshToken(ctx, user.ID, "refresh-token", time.Now().Add(-time.Hour))
		assert.Nil(t, err)

		err = store.RevokeRefreshToken(ctx, "refresh-token")
		assert.Nil(t, err)

		err = store.DeleteExpiredRefreshTokens(ctx)
		assert.Nil(t, err)

		var savedToken string

		err = testDB.QueryRow(
			"SELECT token_hash FROM refresh_tokens WHERE user_id = $1",
			user.ID,
		).Scan(&savedToken)

		assert.NotNil(t, err)
	})
}

func TestUserStoreActivateUserAndGetUserByEmail(t *testing.T) {
	store := &UserStore{DB: testDB}
	ctx := context.Background()

	t.Run("activate user", func(t *testing.T) {
		setupTest(t)
		user := &User{
			Username: "username",
			Email:    "test@test.com",
			Password: "pass",
		}

		token := "verification-token"

		err := store.CreateUserAndVerificationToken(ctx, user, token)
		assert.Nil(t, err)

		err = store.ActivateUser(ctx, token)
		assert.Nil(t, err)

		var isVerified bool
		err = testDB.QueryRow(
			"SELECT is_verified FROM users WHERE id = $1", user.ID,
		).Scan(&isVerified)
		assert.Nil(t, err)

		assert.True(t, isVerified)

		var savedToken string

		err = testDB.QueryRow(
			"SELECT token FROM users_verification_tracking WHERE user_id = $1", user.ID,
		).Scan(&savedToken)

		assert.NotNil(t, err)

		u, err := store.GetUserByEmail(ctx, user.Email)
		assert.Nil(t, err)
		assert.Equal(t, user.ID, u.ID)
	})
}

// func BenchmarkCreateUser(b *testing.B) {
// 	store := &UserStore{DB: testDB}
// 	ctx := context.Background()

// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		user := &User{
// 			Username: fmt.Sprintf("bench%d", i),
// 			Email:    fmt.Sprintf("bench%d@example.com", i),
// 			Password: "pass",
// 		}
// 		store.CreateUserAndVerificationToken(ctx, user, fmt.Sprintf("token%d", i))
// 	}
// }
