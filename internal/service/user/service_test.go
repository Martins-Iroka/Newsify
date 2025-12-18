package user

import (
	"context"
	"errors"
	"testing"
	"time"

	"com.martdev.newsify/config"
	"com.martdev.newsify/internal/auth/password"
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

func TestServiceLoginUser(t *testing.T) {
	getUserByEmail := "GetUserByEmail"
	generateToken := "GenerateToken"
	generateRefreshToken := "GenerateRefreshToken"
	createRefreshToken := "CreateRefreshToken"

	req := LoginUserRequest{
		Email:    "test@example.com",
		Password: "12345",
	}

	t.Run("user login successful", func(t *testing.T) {
		mockStore := new(MockUserStorer)
		mockAuthenticator := new(MockAuthenticator)
		mockOTP := new(MockOTPVerification)
		logger := zaptest.NewLogger(t)

		service := NewService(mockStore, mockAuthenticator, mockOTP, logger.Sugar(), config.Config)

		hashedPassword, err := password.HashPassword("12345")
		require.NoError(t, err)

		existingUser := &dbuser.User{
			ID:       5,
			Email:    "test@example.com",
			Password: hashedPassword,
		}

		mockStore.On(getUserByEmail, t.Context(), req.Email).Return(existingUser, nil)

		mockAuthenticator.On(generateToken, mock.Anything).Return("accessToken", nil)

		mockAuthenticator.On(generateRefreshToken).Return("refreshToken", nil)

		mockStore.On(createRefreshToken, t.Context(), mock.Anything, mock.Anything, mock.Anything).Return(nil)

		loginResponse, err := service.LoginUser(t.Context(), req)

		require.NoError(t, err)
		require.NotNil(t, loginResponse)
		assert.Equal(t, "accessToken", loginResponse.AccessToken)
		assert.Equal(t, "refreshToken", loginResponse.RefreshToken)
		assert.Equal(t, int64(5), loginResponse.UserID)

		mockStore.AssertExpectations(t)
		mockAuthenticator.AssertExpectations(t)
	})

	t.Run("get user by email should return error", func(t *testing.T) {
		mockStore := new(MockUserStorer)
		mockAuthenticator := new(MockAuthenticator)
		mockOTP := new(MockOTPVerification)
		logger := zaptest.NewLogger(t)

		service := NewService(mockStore, mockAuthenticator, mockOTP, logger.Sugar(), config.Config)

		dbError := errors.New("not found")
		mockStore.On(getUserByEmail, t.Context(), req.Email).Return(nil, dbError)

		loginResponse, err := service.LoginUser(t.Context(), req)
		require.Nil(t, loginResponse)
		require.Error(t, err)
		assert.Equal(t, dbError, err)

		mockStore.AssertExpectations(t)
		mockStore.AssertNotCalled(t, createRefreshToken)
		mockAuthenticator.AssertNotCalled(t, generateToken)
		mockAuthenticator.AssertNotCalled(t, generateRefreshToken)
	})

	t.Run("compare password returns error", func(t *testing.T) {
		mockStore := new(MockUserStorer)
		mockAuthenticator := new(MockAuthenticator)
		mockOTP := new(MockOTPVerification)
		logger := zaptest.NewLogger(t)

		service := NewService(mockStore, mockAuthenticator, mockOTP, logger.Sugar(), config.Config)

		hashedPassword, err := password.HashPassword("123456")
		require.NoError(t, err)

		existingUser := &dbuser.User{
			ID:       5,
			Email:    "test@example.com",
			Password: hashedPassword,
		}

		mockStore.On(getUserByEmail, t.Context(), req.Email).Return(existingUser, nil)

		loginResponse, err := service.LoginUser(t.Context(), req)
		require.Nil(t, loginResponse)
		require.Error(t, err)
		assert.ErrorContains(t, err, "incorrect username or password")

		mockStore.AssertExpectations(t)
		mockStore.AssertNotCalled(t, createRefreshToken)
		mockAuthenticator.AssertNotCalled(t, generateToken)
		mockAuthenticator.AssertNotCalled(t, generateRefreshToken)
	})

	t.Run("generate token returns error", func(t *testing.T) {
		mockStore := new(MockUserStorer)
		mockAuthenticator := new(MockAuthenticator)
		mockOTP := new(MockOTPVerification)
		logger := zaptest.NewLogger(t)

		service := NewService(mockStore, mockAuthenticator, mockOTP, logger.Sugar(), config.Config)

		hashedPassword, err := password.HashPassword("12345")
		require.NoError(t, err)

		existingUser := &dbuser.User{
			ID:       5,
			Email:    "test@example.com",
			Password: hashedPassword,
		}

		mockStore.On(getUserByEmail, t.Context(), req.Email).Return(existingUser, nil)

		generateTokenError := errors.New("failed to generate token")
		mockAuthenticator.On(generateToken, mock.Anything).Return("", generateTokenError)

		response, err := service.LoginUser(t.Context(), req)
		require.Nil(t, response)
		require.Error(t, err)
		assert.ErrorIs(t, err, generateTokenError)

		mockStore.AssertExpectations(t)
		mockAuthenticator.AssertExpectations(t)
	})

	t.Run("generate refresh token returns error", func(t *testing.T) {
		mockStore := new(MockUserStorer)
		mockAuthenticator := new(MockAuthenticator)
		mockOTP := new(MockOTPVerification)
		logger := zaptest.NewLogger(t)

		service := NewService(mockStore, mockAuthenticator, mockOTP, logger.Sugar(), config.Config)

		hashedPassword, err := password.HashPassword("12345")
		require.NoError(t, err)

		existingUser := &dbuser.User{
			ID:       5,
			Email:    "test@example.com",
			Password: hashedPassword,
		}

		mockStore.On(getUserByEmail, t.Context(), req.Email).Return(existingUser, nil)

		mockAuthenticator.On(generateToken, mock.Anything).Return("access_token", nil)

		generateRefreshTokenError := errors.New("failed to generate token")
		mockAuthenticator.On(generateRefreshToken).Return("", generateRefreshTokenError)

		response, err := service.LoginUser(t.Context(), req)
		require.Nil(t, response)
		require.Error(t, err)
		require.ErrorIs(t, err, generateRefreshTokenError)

		mockStore.AssertExpectations(t)
		mockStore.AssertNotCalled(t, createRefreshToken)
		mockAuthenticator.AssertExpectations(t)
	})

	t.Run("create refresh token returns error", func(t *testing.T) {
		mockStore := new(MockUserStorer)
		mockAuthenticator := new(MockAuthenticator)
		mockOTP := new(MockOTPVerification)
		logger := zaptest.NewLogger(t)

		service := NewService(mockStore, mockAuthenticator, mockOTP, logger.Sugar(), config.Config)

		hashedPassword, err := password.HashPassword("12345")
		require.NoError(t, err)

		existingUser := &dbuser.User{
			ID:       5,
			Email:    "test@example.com",
			Password: hashedPassword,
		}

		mockStore.On(getUserByEmail, t.Context(), req.Email).Return(existingUser, nil)

		mockAuthenticator.On(generateToken, mock.Anything).Return("access_token", nil)

		mockAuthenticator.On(generateRefreshToken).Return("refresh_token", nil)

		dbError := errors.New("failed to generate token")
		mockStore.On(createRefreshToken, t.Context(), existingUser.ID, mock.Anything, mock.Anything).Return(dbError)

		response, err := service.LoginUser(t.Context(), req)
		require.Nil(t, response)
		require.Error(t, err)
		require.ErrorIs(t, err, dbError)

		mockStore.AssertExpectations(t)
		mockAuthenticator.AssertExpectations(t)
	})
}

func TestRefreshtoken(t *testing.T) {

	getUserByRefreshToken := "GetUserByRefreshToken"
	generateToken := "GenerateToken"

	req := RefreshTokenRequest{
		RefreshToken: "refresh_token",
	}

	t.Run("refresh token successful", func(t *testing.T) {
		mockStore := new(MockUserStorer)
		mockAuthenticator := new(MockAuthenticator)
		mockOTP := new(MockOTPVerification)
		logger := zaptest.NewLogger(t)

		service := NewService(mockStore, mockAuthenticator, mockOTP, logger.Sugar(), config.Config)

		existingUser := &dbuser.User{
			ID:    5,
			Email: "test@example.com",
		}
		mockStore.On(getUserByRefreshToken, t.Context(), mock.Anything).Return(existingUser, nil)

		mockAuthenticator.On(generateToken, mock.Anything).Return("new_access_token", nil)

		response, err := service.RefreshToken(t.Context(), req)

		require.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, "new_access_token", response.AccessToken)

		mockStore.AssertExpectations(t)
		mockAuthenticator.AssertExpectations(t)
	})

	t.Run("generate token returns error", func(t *testing.T) {
		mockStore := new(MockUserStorer)
		mockAuthenticator := new(MockAuthenticator)
		mockOTP := new(MockOTPVerification)
		logger := zaptest.NewLogger(t)

		service := NewService(mockStore, mockAuthenticator, mockOTP, logger.Sugar(), config.Config)

		dbError := errors.New("no user found")
		mockStore.On(getUserByRefreshToken, t.Context(), mock.Anything).Return(nil, dbError)

		response, err := service.RefreshToken(t.Context(), req)

		require.Error(t, err)
		require.Nil(t, response)
		assert.ErrorIs(t, err, dbError)

		mockStore.AssertExpectations(t)
		mockAuthenticator.AssertExpectations(t)
		mockAuthenticator.AssertNotCalled(t, generateToken)
	})

	t.Run("refresh token successful", func(t *testing.T) {
		mockStore := new(MockUserStorer)
		mockAuthenticator := new(MockAuthenticator)
		mockOTP := new(MockOTPVerification)
		logger := zaptest.NewLogger(t)

		service := NewService(mockStore, mockAuthenticator, mockOTP, logger.Sugar(), config.Config)

		existingUser := &dbuser.User{
			ID:    5,
			Email: "test@example.com",
		}
		mockStore.On(getUserByRefreshToken, t.Context(), mock.Anything).Return(existingUser, nil)

		generateTokenError := errors.New("error generating token")
		mockAuthenticator.On(generateToken, mock.Anything).Return("", generateTokenError)

		response, err := service.RefreshToken(t.Context(), req)

		require.Error(t, err)
		require.Nil(t, response)
		assert.ErrorIs(t, err, generateTokenError)

		mockStore.AssertExpectations(t)
		mockAuthenticator.AssertExpectations(t)
	})
}

func TestLogoutUser(t *testing.T) {

	revokeRefreshToken := "RevokeRefreshToken"

	refreshToken := "refresh_token"

	t.Run("revoke refresh token when user logs out", func(t *testing.T) {
		mockStore := new(MockUserStorer)
		mockAuthenticator := new(MockAuthenticator)
		mockOTPVerification := new(MockOTPVerification)
		logger := zaptest.NewLogger(t)

		service := NewService(mockStore, mockAuthenticator, mockOTPVerification, logger.Sugar(), config.Config)

		mockStore.On(revokeRefreshToken, t.Context(), mock.Anything).Return(nil)

		err := service.LogoutUser(t.Context(), refreshToken)
		assert.NoError(t, err)
		mockStore.AssertExpectations(t)
	})

	t.Run("revoke refresh token returns error", func(t *testing.T) {
		mockStore := new(MockUserStorer)
		mockAuthenticator := new(MockAuthenticator)
		mockOTPVerification := new(MockOTPVerification)
		logger := zaptest.NewLogger(t)

		service := NewService(mockStore, mockAuthenticator, mockOTPVerification, logger.Sugar(), config.Config)

		dbError := errors.New("db error")
		mockStore.On(revokeRefreshToken, t.Context(), mock.Anything).Return(dbError)

		err := service.LogoutUser(t.Context(), refreshToken)
		require.Error(t, err)
		assert.ErrorIs(t, err, dbError)
		mockStore.AssertExpectations(t)
	})

}
