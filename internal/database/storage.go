package database

import (
	"context"
	"database/sql"
	"time"

	"com.martdev.newsify/internal/database/user"
)

type Storage struct {
	User interface {
		ActivateUser(ctx context.Context, token string) error
		CreateUserAndVerificationToken(ctx context.Context, user *user.User, token string) error
		CreateRefreshToken(ctx context.Context, userID int64, tokenHash string, expiresAt time.Time) error
		DeleteExpiredRefreshTokens(context.Context) error
		DeleteUser(ctx context.Context, userID int64) error
		GetUserByEmail(ctx context.Context, email string) (*user.User, error)
		GetUserByID(ctx context.Context, userID int64) (*user.User, error)
		GetUserByRefreshToken(ctx context.Context, tokenHash string) (*user.User, error)
		RevokeRefreshToken(ctx context.Context, tokenHash string) error
	}
}

func NewStorage(db *sql.DB) Storage {
	return Storage{
		User: &user.UserStore{DB: db},
	}
}
