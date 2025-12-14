package user

import (
	"context"
	"errors"
	"testing"
	"time"

	"com.martdev.newsify/config"
	dbuser "com.martdev.newsify/internal/database/user"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

type MockUserStorer struct {
	mock.Mock
}

func (m *MockUserStorer) ActivateUser(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *MockUserStorer) CreateUserAndVerificationToken(ctx context.Context, user *dbuser.User, token string) error {
	args := m.Called(ctx, user, token)
	return args.Error(0)
}

func (m *MockUserStorer) CreateRefreshToken(ctx context.Context, userID int64, tokenHash string, expiresAt time.Time) error {
	args := m.Called(ctx, userID, tokenHash, expiresAt)
	return args.Error(0)
}

func (m *MockUserStorer) DeleteExpiredRefreshTokens(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockUserStorer) DeleteUser(ctx context.Context, userId int64) error {
	args := m.Called(ctx, userId)
	return args.Error(0)
}

func (m *MockUserStorer) GetUserByEmail(ctx context.Context, email string) (*dbuser.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*dbuser.User), args.Error(1)
}

func (m *MockUserStorer) GetUserByID(ctx context.Context, userID int64) (*dbuser.User, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*dbuser.User), args.Error(1)
}

func (m *MockUserStorer) GetUserByRefreshToken(ctx context.Context, tokenHash string) (*dbuser.User, error) {
	args := m.Called(ctx, tokenHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*dbuser.User), args.Error(1)
}

func (m *MockUserStorer) RevokeRefreshToken(ctx context.Context, tokenHash string) error {
	args := m.Called(ctx, tokenHash)
	return args.Error(0)
}

type MockAuthenticator struct {
	mock.Mock
}

func (m *MockAuthenticator) GenerateToken(claims jwt.Claims) (string, error) {
	args := m.Called(claims)
	return args.String(0), args.Error(1)
}

func (m *MockAuthenticator) GenerateRefreshToken() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *MockAuthenticator) ValidateToken(token string) (*jwt.Token, error) {
	args := m.Called(token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*jwt.Token), args.Error(1)
}

type MockOTPVerification struct {
	mock.Mock
}

func (m *MockOTPVerification) SendVerificationCode(email string) error {
	args := m.Called(email)
	return args.Error(0)
}

func (m *MockOTPVerification) VerifyCode(email, code string) error {
	args := m.Called(email, code)
	return args.Error(0)
}

func TestServiceRegisterUser(t *testing.T) {
	req := RegisterUserRequest{
		Email:    "test@example.com",
		Username: "username",
		Password: "12345",
	}
	createUserAndVerificationToken := "CreateUserAndVerificationToken"
	sendVerificationCode := "SendVerificationCode"
	t.Run("register user successfully", func(t *testing.T) {
		mockStore := new(MockUserStorer)
		mockAuthenticator := new(MockAuthenticator)
		mockOTP := new(MockOTPVerification)
		logger := zaptest.NewLogger(t)

		service := NewService(mockStore, mockAuthenticator, mockOTP, logger.Sugar(), config.Config)
		verificationToken := "verification-token"

		mockStore.On(createUserAndVerificationToken,
			mock.Anything,
			mock.MatchedBy(func(u *dbuser.User) bool {
				return u.Email == req.Email &&
					u.Username == req.Username &&
					u.Password != req.Password
			}), verificationToken,
		).Return(nil)

		mockOTP.On(sendVerificationCode, req.Email).Return(nil)

		tokenResponse, err := service.RegisterUser(t.Context(), req, verificationToken)

		require.NoError(t, err)
		require.NotNil(t, tokenResponse)
		assert.Equal(t, verificationToken, tokenResponse.Token)

		mockStore.AssertExpectations(t)
		mockOTP.AssertExpectations(t)
	})

	t.Run("database error", func(t *testing.T) {
		mockStore := new(MockUserStorer)
		mockAuthenticator := new(MockAuthenticator)
		mockOTP := new(MockOTPVerification)
		logger := zaptest.NewLogger(t)

		service := NewService(mockStore, mockAuthenticator, mockOTP, logger.Sugar(), config.Config)
		dbError := errors.New("database connection failed")
		mockStore.On(createUserAndVerificationToken, mock.Anything, mock.Anything, "token").Return(dbError)

		_, err := service.RegisterUser(t.Context(), req, "token")

		require.Error(t, err)
		assert.Equal(t, dbError, err)

		mockStore.AssertExpectations(t)
		mockOTP.AssertNotCalled(t, sendVerificationCode)
	})

	t.Run("send verification fails delete user succcessful", func(t *testing.T) {
		mockStore := new(MockUserStorer)
		mockAuthenticator := new(MockAuthenticator)
		mockOTP := new(MockOTPVerification)
		logger := zaptest.NewLogger(t)

		service := NewService(mockStore, mockAuthenticator, mockOTP, logger.Sugar(), config.Config)
		mockStore.On(createUserAndVerificationToken, mock.Anything, mock.Anything, "token").Return(nil)

		otpError := errors.New("failed to send verification code")
		mockOTP.On(sendVerificationCode, req.Email).Return(otpError)

		mockStore.On("DeleteUser", t.Context(), mock.Anything).Return(nil)

		tokenResponse, err := service.RegisterUser(t.Context(), req, "token")

		require.Error(t, err)
		require.Nil(t, tokenResponse)
		assert.Equal(t, otpError, err)

		mockOTP.AssertExpectations(t)
		mockStore.AssertCalled(t, "DeleteUser", t.Context(), mock.Anything)
	})

	t.Run("send verification fails delete user failed", func(t *testing.T) {
		mockStore := new(MockUserStorer)
		mockAuthenticator := new(MockAuthenticator)
		mockOTP := new(MockOTPVerification)
		logger := zaptest.NewLogger(t)

		service := NewService(mockStore, mockAuthenticator, mockOTP, logger.Sugar(), config.Config)
		mockStore.On(createUserAndVerificationToken, mock.Anything, mock.Anything, "token").Return(nil)

		otpError := errors.New("failed to send verification code")
		mockOTP.On(sendVerificationCode, req.Email).Return(otpError)

		deleteError := errors.New("database error")
		mockStore.On("DeleteUser", t.Context(), mock.Anything).Return(deleteError)

		tokenResponse, err := service.RegisterUser(t.Context(), req, "token")

		require.Error(t, err)
		require.Nil(t, tokenResponse)
		assert.Equal(t, otpError, err)

		mockOTP.AssertExpectations(t)
		mockStore.AssertCalled(t, "DeleteUser", t.Context(), mock.Anything)
	})
}

func TestVerifyUser(t *testing.T) {

	req := VerifyUserRequest{
		Code:  "12345",
		Email: "t@example.com",
		Token: "token",
	}

	verifyCode := "VerifyCode"
	activateUser := "ActivateUser"

	t.Run("user verification successful", func(t *testing.T) {
		mockStore := new(MockUserStorer)
		mockAuthenticator := new(MockAuthenticator)
		mockOTP := new(MockOTPVerification)
		logger := zaptest.NewLogger(t)

		service := NewService(mockStore, mockAuthenticator, mockOTP, logger.Sugar(), config.Config)

		mockOTP.On(verifyCode, req.Email, req.Code).Return(nil)

		mockStore.On(activateUser, t.Context(), req.Token).Return(nil)

		verifyUserResponse, err := service.VerifyUser(t.Context(), req)

		require.NoError(t, err)
		require.NotNil(t, verifyUserResponse)
		assert.Equal(t, "verified", verifyUserResponse.Status)

		mockOTP.AssertExpectations(t)
		mockStore.AssertExpectations(t)
	})

	t.Run("verify code returns error", func(t *testing.T) {
		mockStore := new(MockUserStorer)
		mockAuthenticator := new(MockAuthenticator)
		mockOTP := new(MockOTPVerification)
		logger := zaptest.NewLogger(t)

		service := NewService(mockStore, mockAuthenticator, mockOTP, logger.Sugar(), config.Config)

		otpError := errors.New("failed to verify code")
		mockOTP.On(verifyCode, req.Email, req.Code).Return(otpError)

		verifyUserResponse, err := service.VerifyUser(t.Context(), req)

		require.Error(t, err)
		require.Nil(t, verifyUserResponse)
		assert.Equal(t, otpError, err)

		mockOTP.AssertExpectations(t)
		mockStore.AssertNotCalled(t, activateUser)
	})

	t.Run("user activation failed", func(t *testing.T) {
		mockStore := new(MockUserStorer)
		mockAuthenticator := new(MockAuthenticator)
		mockOTP := new(MockOTPVerification)
		logger := zaptest.NewLogger(t)

		service := NewService(mockStore, mockAuthenticator, mockOTP, logger.Sugar(), config.Config)

		mockOTP.On(verifyCode, req.Email, req.Code).Return(nil)

		activationError := errors.New("user activation error")
		mockStore.On(activateUser, t.Context(), req.Token).Return(activationError)

		verifyUserResponse, err := service.VerifyUser(t.Context(), req)

		require.Error(t, err)
		require.Nil(t, verifyUserResponse)
		assert.Equal(t, activationError, err)

		mockOTP.AssertExpectations(t)
		mockStore.AssertExpectations(t)
	})
}
