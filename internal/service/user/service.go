package user

import (
	"context"
	"time"

	"com.martdev.newsify/internal/auth"
	dbuser "com.martdev.newsify/internal/database/user"
)

type UserStorer interface {
	ActivateUser(ctx context.Context, token string) error
	CreateUserAndVerificationToken(ctx context.Context, user *dbuser.User, token string) error
	CreateRefreshToken(ctx context.Context, userID int64, tokenHash string, expiresAt time.Time) error
	DeleteExpiredRefreshTokens(context.Context) error
	DeleteUser(ctx context.Context, userID int64) error
	GetUserByEmail(ctx context.Context, email string) (*dbuser.User, error)
	GetUserByID(ctx context.Context, userID int64) (*dbuser.User, error)
	GetUserByRefreshToken(ctx context.Context, tokenHash string) (*dbuser.User, error)
	RevokeRefreshToken(ctx context.Context, tokenHash string) error
}

type Service struct {
	store UserStorer
	auth  auth.Authenticator
	otp   auth.OTPVerification
}

func NewService(store UserStorer, auth auth.Authenticator, otp auth.OTPVerification) *Service {
	return &Service{
		store: store,
		auth:  auth,
		otp:   otp,
	}
}

type RegisterUserRequest struct {
	Email    string `json:"email" validate:"required,email,max=255"`
	Password string `json:"password" validate:"required,min=5,max=72"`
	Username string `json:"username" validate:"required,max=100"`
}

func (s *Service) RegisterUser(ctx context.Context, req RegisterUserRequest) error {
	return nil
}
