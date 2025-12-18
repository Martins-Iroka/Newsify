package user

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"com.martdev.newsify/config"
	"com.martdev.newsify/internal/auth"
	"com.martdev.newsify/internal/auth/password"
	dbuser "com.martdev.newsify/internal/database/user"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

type UserService interface {
	RegisterUser(ctx context.Context, req RegisterUserRequest, token string) (*TokenResponse, error)
	VerifyUser(ctx context.Context, req VerifyUserRequest) (*VerifyUserResponse, error)
	LoginUser(ctx context.Context, req LoginUserRequest) (*LoginUserResponse, error)
	RefreshToken(ctx context.Context, req RefreshTokenRequest) (*RefreshTokenResponse, error)
	LogoutUser(ctx context.Context, refreshToken string) error
}

type Service struct {
	store  dbuser.UserStorer
	auth   auth.Authenticator
	otp    auth.OTPVerification
	logger *zap.SugaredLogger
	config config.Configuration
}

// todo add role base login
func NewService(store dbuser.UserStorer, auth auth.Authenticator, otp auth.OTPVerification, logger *zap.SugaredLogger, config config.Configuration) *Service {
	return &Service{
		store:  store,
		auth:   auth,
		otp:    otp,
		logger: logger,
		config: config,
	}
}

type RegisterUserRequest struct {
	Email    string `json:"email" validate:"required,email,max=255"`
	Password string `json:"password" validate:"required,min=5,max=72"`
	Username string `json:"username" validate:"required,max=100"`
}

type TokenResponse struct {
	Token string `json:"token"`
}

func (s *Service) RegisterUser(ctx context.Context, req RegisterUserRequest, verificationToken string) (*TokenResponse, error) {
	hashedPassword, err := password.HashPassword(req.Password)
	if err != nil {
		return nil, err
	}

	user := &dbuser.User{
		Username: req.Username,
		Email:    req.Email,
		Password: hashedPassword,
	}

	if err := s.store.CreateUserAndVerificationToken(ctx, user, verificationToken); err != nil {
		return nil, err
	}

	if err := s.otp.SendVerificationCode(user.Email); err != nil {
		s.logger.Errorw("failed to send verification code", "email", user.Email, "error", err)
		if deleteErr := s.store.DeleteUser(ctx, user.ID); deleteErr != nil {
			s.logger.Errorw("error deleting user after email failure", "error", deleteErr, "email", user.Email)
		} else {
			s.logger.Infow("user deleted after email failure", "user_id", user.ID)
		}
		return nil, err
	}

	tokenResponse := &TokenResponse{
		Token: verificationToken,
	}

	return tokenResponse, nil
}

type VerifyUserRequest struct {
	Code  string `json:"code" validate:"required,len=6"`
	Email string `json:"email" validate:"required,email,max=255"`
	Token string `json:"token" validate:"required"`
}

type VerifyUserResponse struct {
	Status string `json:"status"`
}

func (s *Service) VerifyUser(ctx context.Context, req VerifyUserRequest) (*VerifyUserResponse, error) {

	if err := s.otp.VerifyCode(req.Email, req.Code); err != nil {
		s.logger.Errorw("failed to verify code", "email", req.Email, "error", err.Error())
		return nil, err
	}

	if err := s.store.ActivateUser(ctx, req.Token); err != nil {
		s.logger.Errorw("failed to activate user", "email", req.Email, "error", err.Error())
		return nil, err
	}

	verifyUserResponse := VerifyUserResponse{Status: "verified"}

	return &verifyUserResponse, nil
}

type LoginUserRequest struct {
	Email    string `json:"email" validate:"required,email,max=255"`
	Password string `json:"password" validate:"required,min=5,max=72"`
}

type LoginUserResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	UserID       int64  `json:"user_id"`
}

// todo decide where you would want to hash and maintain it
func (s *Service) LoginUser(ctx context.Context, req LoginUserRequest) (*LoginUserResponse, error) {

	user, err := s.store.GetUserByEmail(ctx, req.Email)
	if err != nil {
		s.logger.Errorw("failed to get user by email", "email", req.Email, "error", err)
		return nil, err
	}

	if err := password.ComparePasswords(user.Password, req.Password); err != nil {
		return nil, errors.New("incorrect username or password")
	}

	claims := jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(s.config.AuthConfig.Exp).Unix(),
		"iat": time.Now().Unix(),
		"nbf": time.Now().Unix(),
		"iss": s.config.AuthConfig.Iss,
		"aud": s.config.AuthConfig.Iss,
	}

	accessToken, err := s.auth.GenerateToken(claims)
	if err != nil {
		s.logger.Errorw("token generation failed", "error", err.Error())
		return nil, err
	}

	refreshToken, err := s.auth.GenerateRefreshToken()
	if err != nil {
		s.logger.Errorw("failed to generate refresh token", "error", err.Error())
		return nil, err
	}

	hash := sha256.Sum256([]byte(refreshToken))
	tokenHash := hex.EncodeToString(hash[:])

	refreshExpiry := time.Now().Add(1 * 24 * time.Hour)

	if err := s.store.CreateRefreshToken(ctx, user.ID, tokenHash, refreshExpiry); err != nil {
		s.logger.Errorw("failed to create refresh token", "error", err.Error())
		return nil, err
	}

	response := LoginUserResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		UserID:       user.ID,
	}

	return &response, nil

}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}
type RefreshTokenResponse struct {
	AccessToken string `json:"access_token"`
}

func (s *Service) RefreshToken(ctx context.Context, req RefreshTokenRequest) (*RefreshTokenResponse, error) {

	hash := sha256.Sum256([]byte(req.RefreshToken))
	tokenHash := hex.EncodeToString(hash[:])
	user, err := s.store.GetUserByRefreshToken(ctx, tokenHash)
	if err != nil {
		return nil, err
	}

	claims := jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(s.config.AuthConfig.Exp).Unix(),
		"iat": time.Now().Unix(),
		"nbf": time.Now().Unix(),
		"iss": s.config.AuthConfig.Iss,
		"aud": s.config.AuthConfig.Iss,
	}

	accessToken, err := s.auth.GenerateToken(claims)
	if err != nil {
		return nil, err
	}

	response := RefreshTokenResponse{
		AccessToken: accessToken,
	}
	return &response, nil
}

func (s *Service) LogoutUser(ctx context.Context, refreshToken string) error {

	hash := sha256.Sum256([]byte(refreshToken))
	tokenHash := hex.EncodeToString(hash[:])

	if err := s.store.RevokeRefreshToken(ctx, tokenHash); err != nil {
		return err
	}
	return nil
}
