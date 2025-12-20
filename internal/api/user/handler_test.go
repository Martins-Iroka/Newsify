package user

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	userService "com.martdev.newsify/internal/service/user"
	"com.martdev.newsify/internal/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

type MockService struct {
	mock.Mock
}

func (m *MockService) RegisterUser(ctx context.Context, req userService.RegisterUserRequest, token string) (*userService.TokenResponse, error) {
	arg := m.Called(ctx, req, token)
	if arg.Get(0) == nil {
		return nil, arg.Error(1)
	}

	return arg.Get(0).(*userService.TokenResponse), arg.Error(1)
}

func (m *MockService) VerifyUser(ctx context.Context, req userService.VerifyUserRequest) (*userService.VerifyUserResponse, error) {
	arg := m.Called(ctx, req)
	if arg.Get(0) == nil {
		return nil, arg.Error(1)
	}
	return arg.Get(0).(*userService.VerifyUserResponse), arg.Error(1)
}

func (m *MockService) LoginUser(ctx context.Context, req userService.LoginUserRequest) (*userService.LoginUserResponse, error) {
	arg := m.Called(ctx, req)
	if arg.Get(0) == nil {
		return nil, arg.Error(1)
	}
	return arg.Get(0).(*userService.LoginUserResponse), arg.Error(1)
}

func (m *MockService) RefreshToken(ctx context.Context, req userService.RefreshTokenRequest) (*userService.RefreshTokenResponse, error) {
	arg := m.Called(ctx, req)
	if arg.Get(0) == nil {
		return nil, arg.Error(1)
	}
	return arg.Get(0).(*userService.RefreshTokenResponse), arg.Error(1)
}

func (m *MockService) LogoutUser(ctx context.Context, refreshToken string) error {
	arg := m.Called(ctx, refreshToken)
	return arg.Error(0)
}

func TestRegisterUserHandler(t *testing.T) {
	mockService := new(MockService)
	logger := zaptest.NewLogger(t).Sugar()
	handler := NewHandler(mockService, logger)
	RegisterUser := "RegisterUser"

	t.Run("Success", func(t *testing.T) {
		reqBody := userService.RegisterUserRequest{
			Email:    "test@example.com",
			Username: "martdev",
			Password: "123456",
		}

		expectResp := &userService.TokenResponse{Token: "verification-token"}

		mockService.On(RegisterUser, mock.Anything, reqBody, mock.AnythingOfType("string")).
			Return(expectResp, nil)

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.registerUserHandler(w, req)

		require.NoError(t, err)
		assert.Equal(t, http.StatusCreated, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("Duplicate email", func(t *testing.T) {
		reqBody := userService.RegisterUserRequest{
			Email:    "duplicate@example.com",
			Username: "user",
			Password: "password",
		}

		mockService.On(RegisterUser, mock.Anything, reqBody, mock.Anything).
			Return(nil, util.ErrorDuplicateEmail)

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.registerUserHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("Duplicate username", func(t *testing.T) {
		reqBody := userService.RegisterUserRequest{
			Email:    "test@example.com",
			Username: "duplicateUsername",
			Password: "password",
		}

		mockService.On(RegisterUser, mock.Anything, reqBody, mock.Anything).
			Return(nil, util.ErrorDuplicateUsername)

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.registerUserHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("wrong email format", func(t *testing.T) {
		reqBody := userService.RegisterUserRequest{
			Email:    "wrongEmailFormat",
			Password: "123456",
			Username: "martdev",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.registerUserHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
		mockService.AssertNotCalled(t, RegisterUser)
	})

	t.Run("password less than min", func(t *testing.T) {
		reqBody := userService.RegisterUserRequest{
			Email:    "e@example.com",
			Password: "12",
			Username: "martdev",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.registerUserHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
		mockService.AssertNotCalled(t, RegisterUser)
	})

	t.Run("password greater than max", func(t *testing.T) {
		reqBody := userService.RegisterUserRequest{
			Email:    "e@example.com",
			Password: strings.Repeat("1", 73),
			Username: "martdev",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.registerUserHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
		mockService.AssertNotCalled(t, RegisterUser)
	})

	t.Run("username is missing", func(t *testing.T) {
		reqBody := userService.RegisterUserRequest{
			Email:    "e@example.com",
			Password: "123456",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.registerUserHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
		mockService.AssertNotCalled(t, RegisterUser)
	})

	t.Run("username is greater than max", func(t *testing.T) {
		reqBody := userService.RegisterUserRequest{
			Email:    "e@example.com",
			Password: "123456",
			Username: strings.Repeat("m", 101),
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.registerUserHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
		mockService.AssertNotCalled(t, RegisterUser)
	})

	t.Run("unknown field passed as parameter", func(t *testing.T) {
		reqBody := struct {
			Email       string `json:"email" validate:"required,email,max=255"`
			Password    string `json:"password" validate:"required,min=5,max=72"`
			Username    string `json:"username" validate:"required,max=100"`
			Unknowfield string `json:"unknown"`
		}{
			Email:       "e@email.com",
			Password:    "123456",
			Username:    "martdev",
			Unknowfield: "unknown",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.registerUserHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
		mockService.AssertNotCalled(t, RegisterUser)
	})

	t.Run("internal server error", func(t *testing.T) {
		reqBody := userService.RegisterUserRequest{
			Email:    "test@example.com",
			Username: "user",
			Password: "password",
		}
		dbError := errors.New("dbError")
		mockService.On(RegisterUser, mock.Anything, reqBody, mock.Anything).
			Return(nil, dbError)

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.registerUserHandler(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		mockService.AssertExpectations(t)
	})
}
