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
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
)

type MockService struct {
	mock.Mock
}

func (m *MockService) RegisterUser(ctx context.Context, req userService.RegisterUserRequest, token string) (*userService.RegisterUserResponse, error) {
	arg := m.Called(ctx, req, token)
	if arg.Get(0) == nil {
		return nil, arg.Error(1)
	}

	return arg.Get(0).(*userService.RegisterUserResponse), arg.Error(1)
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

func (m *MockService) ResendOTP(ctx context.Context, req userService.ResendOTPRequest) (*userService.ResendOTPResponse, error) {
	arg := m.Called(ctx, req)
	if arg.Get(0) == nil {
		return nil, arg.Error(1)
	}
	return arg.Get(0).(*userService.ResendOTPResponse), arg.Error(1)
}

func TestRegisterUserHandler(t *testing.T) {
	mockService := new(MockService)
	logger := zaptest.NewLogger(t).Sugar()
	handler := NewHandler(mockService, logger)
	RegisterUser := "RegisterUser"
	const registerPath = "/register"

	t.Run("Success", func(t *testing.T) {
		reqBody := userService.RegisterUserRequest{
			Email:    "test1@example.com",
			Username: "martdev",
			Password: "123456",
		}

		expectResp := &userService.RegisterUserResponse{Token: "verification-token"}

		mockService.On(RegisterUser, mock.Anything, reqBody, mock.AnythingOfType("string")).
			Return(expectResp, nil)

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, registerPath, bytes.NewReader(body))
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
		req := httptest.NewRequest(http.MethodPost, registerPath, bytes.NewReader(body))
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
		req := httptest.NewRequest(http.MethodPost, registerPath, bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.registerUserHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("wrong login email format", func(t *testing.T) {
		reqBody := userService.RegisterUserRequest{
			Email:    "wrongEmailFormat",
			Password: "123456",
			Username: "martdev",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, registerPath, bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.registerUserHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
		mockService.AssertNotCalled(t, RegisterUser)
	})

	t.Run("password less than min", func(t *testing.T) {
		reqBody := userService.RegisterUserRequest{
			Email:    "test2@example.com",
			Password: "12",
			Username: "martdev",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, registerPath, bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.registerUserHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
		mockService.AssertNotCalled(t, RegisterUser)
	})

	t.Run("password greater than max", func(t *testing.T) {
		reqBody := userService.RegisterUserRequest{
			Email:    "test3@example.com",
			Password: strings.Repeat("1", 73),
			Username: "martdev",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, registerPath, bytes.NewReader(body))
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
		req := httptest.NewRequest(http.MethodPost, registerPath, bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.registerUserHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
		mockService.AssertNotCalled(t, RegisterUser)
	})

	t.Run("username is greater than max", func(t *testing.T) {
		reqBody := userService.RegisterUserRequest{
			Email:    "test6@example.com",
			Password: "123456",
			Username: strings.Repeat("m", 101),
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, registerPath, bytes.NewReader(body))
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
		req := httptest.NewRequest(http.MethodPost, registerPath, bytes.NewReader(body))
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
		req := httptest.NewRequest(http.MethodPost, registerPath, bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.registerUserHandler(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		mockService.AssertExpectations(t)
	})
}

func TestVerifyUser(t *testing.T) {
	mockService := new(MockService)
	logger := zaptest.NewLogger(t).Sugar()
	handler := NewHandler(mockService, logger)
	VerifyUser := "VerifyUser"
	verifyPath := "/verify"

	t.Run("verification successful", func(t *testing.T) {
		reqBody := userService.VerifyUserRequest{
			Code:  "123456",
			Email: "testEmail@example.com",
			Token: "verification_token",
		}

		response := &userService.VerifyUserResponse{
			Status: "verified",
		}

		mockService.On(VerifyUser, mock.Anything, reqBody).Return(response, nil)

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, verifyPath, bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.verifyUserHandler(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("unknown field added", func(t *testing.T) {
		reqBody := struct {
			Code    string `json:"code" validate:"required,len=6"`
			Email   string `json:"email" validate:"required,email,max=255"`
			Token   string `json:"token" validate:"required"`
			Unknown string `json:"unknown"`
		}{
			Code:    "123456",
			Email:   "ik@example.com",
			Token:   "verification_token",
			Unknown: "unknown",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, verifyPath, bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.verifyUserHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertNotCalled(t, VerifyUser)
	})

	t.Run("wrong email format", func(t *testing.T) {
		reqBody := userService.VerifyUserRequest{
			Code:  "123456",
			Email: "wrong email format",
			Token: "verification_token",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, verifyPath, bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.verifyUserHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertNotCalled(t, VerifyUser)
	})

	t.Run("code exceeds 6", func(t *testing.T) {
		reqBody := userService.VerifyUserRequest{
			Code:  "1234567",
			Email: "mart@email.com",
			Token: "verification_token",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, verifyPath, bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.verifyUserHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertNotCalled(t, VerifyUser)
	})

	t.Run("no token sent", func(t *testing.T) {
		reqBody := userService.VerifyUserRequest{
			Code:  "123456",
			Email: "mart@email.com",
			Token: "",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, verifyPath, bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.verifyUserHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertNotCalled(t, VerifyUser)
	})

	t.Run("not found error returned", func(t *testing.T) {
		reqBody := userService.VerifyUserRequest{
			Code:  "123456",
			Email: "unknownEmail@test.com",
			Token: "verification_token",
		}

		mockService.On(VerifyUser, mock.Anything, reqBody).Return(nil, util.ErrorNotFound)

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, verifyPath, bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.verifyUserHandler(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("db error returns internal server error", func(t *testing.T) {
		reqBody := userService.VerifyUserRequest{
			Code:  "654321",
			Email: "test1@email.com",
			Token: "token",
		}

		dbError := errors.New("db error")

		mockService.On(VerifyUser, mock.Anything, reqBody).Return(nil, dbError)

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, verifyPath, bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.verifyUserHandler(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		mockService.AssertExpectations(t)
	})
}

func TestLoginUser(t *testing.T) {

	mockService := new(MockService)
	logger := zaptest.NewLogger(t).Sugar()
	LoginUser := "LoginUser"
	loginPath := "/login"

	t.Run("login successful", func(t *testing.T) {
		handler := NewHandler(mockService, logger)
		reqBody := userService.LoginUserRequest{
			Email:    "test2@email.com",
			Password: "123456",
		}

		responseBody := &userService.LoginUserResponse{
			AccessToken:  "access_token",
			RefreshToken: "refresh_token",
			UserID:       1,
		}

		mockService.On(LoginUser, mock.Anything, reqBody).Return(responseBody, nil)

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, loginPath, bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.loginUserHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("unknown json field", func(t *testing.T) {
		handler := NewHandler(mockService, logger)
		reqBody := struct {
			Email    string `json:"email" validate:"required,email,max=255"`
			Password string `json:"password" validate:"required,min=5,max=72"`
			Unknown  string `json:"unknown"`
		}{
			Email:    "test3@email.com",
			Password: "hadbeldk",
			Unknown:  "unknown",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, loginPath, bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.loginUserHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
		mockService.AssertNotCalled(t, LoginUser)
	})

	t.Run("wrong email format entered", func(t *testing.T) {
		handler := NewHandler(mockService, logger)
		reqBody := userService.LoginUserRequest{
			Email:    "wrongemailformat",
			Password: "jfidlfjeil",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, loginPath, bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.loginUserHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
		mockService.AssertNotCalled(t, LoginUser)
	})

	t.Run("password is less than min", func(t *testing.T) {
		handler := NewHandler(mockService, logger)
		reqBody := userService.LoginUserRequest{
			Email:    "test15@email.com",
			Password: "thyd",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, loginPath, bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.loginUserHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
		mockService.AssertNotCalled(t, LoginUser)
	})

	t.Run("password is less than min", func(t *testing.T) {
		handler := NewHandler(mockService, logger)
		reqBody := userService.LoginUserRequest{
			Email:    "test25@email.com",
			Password: "thyd",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, loginPath, bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.loginUserHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
		mockService.AssertNotCalled(t, LoginUser)
	})

	t.Run("password is greater than max", func(t *testing.T) {
		handler := NewHandler(mockService, logger)
		reqBody := userService.LoginUserRequest{
			Email:    "test35@email.com",
			Password: strings.Repeat("p", 73),
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, loginPath, bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.loginUserHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
		mockService.AssertNotCalled(t, LoginUser)
	})

	t.Run("not found", func(t *testing.T) {
		handler := NewHandler(mockService, logger)
		reqBody := userService.LoginUserRequest{
			Email:    "test45@email.com",
			Password: "password567",
		}

		mockService.On(LoginUser, mock.Anything, reqBody).Return(nil, util.ErrorNotFound)

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, loginPath, bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.loginUserHandler(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("db error returns internal server error", func(t *testing.T) {
		handler := NewHandler(mockService, logger)
		reqBody := userService.LoginUserRequest{
			Email:    "test55@email.com",
			Password: "password567",
		}

		dbError := errors.New("db error")
		mockService.On(LoginUser, mock.Anything, reqBody).Return(nil, dbError)

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, loginPath, bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.loginUserHandler(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		mockService.AssertExpectations(t)
	})
}

func TestRefreshToken(t *testing.T) {
	mockService := new(MockService)
	logger := zaptest.NewLogger(t).Sugar()
	RefreshToken := "RefreshToken"
	refreshTokenPath := "/refresh"

	t.Run("refresh token successfully", func(t *testing.T) {
		handler := NewHandler(mockService, logger)

		reqBody := userService.RefreshTokenRequest{
			RefreshToken: "refresh_token",
		}

		responseBody := &userService.RefreshTokenResponse{
			AccessToken: "access_token",
		}
		mockService.On(RefreshToken, mock.Anything, reqBody).Return(responseBody, nil)

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, refreshTokenPath, bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.refreshTokenHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("passed unknown field to request", func(t *testing.T) {
		handler := NewHandler(mockService, logger)
		reqBody := struct {
			RefreshToken string `json:"refresh_token" validate:"required"`
			Unknown      string `json:"unknown" validate:"required"`
		}{
			"refresh_token",
			"unknown",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, refreshTokenPath, bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.refreshTokenHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
		mockService.AssertNotCalled(t, RefreshToken)
	})

	t.Run("passed empty refresh token request", func(t *testing.T) {
		handler := NewHandler(mockService, logger)
		reqBody := userService.RefreshTokenRequest{
			RefreshToken: "",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, refreshTokenPath, bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.refreshTokenHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
		mockService.AssertNotCalled(t, RefreshToken)
	})

	t.Run("not found returns unauthorized error", func(t *testing.T) {
		mockService := new(MockService)
		logger := zaptest.NewLogger(t).Sugar()
		handler := NewHandler(mockService, logger)

		reqBody := userService.RefreshTokenRequest{
			RefreshToken: "refresh_token",
		}

		mockService.On(RefreshToken, mock.Anything, reqBody).Return(nil, util.ErrorNotFound)

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, refreshTokenPath, bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.refreshTokenHandler(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("internal server error", func(t *testing.T) {
		mockService := new(MockService)
		logger := zaptest.NewLogger(t).Sugar()
		handler := NewHandler(mockService, logger)

		reqBody := userService.RefreshTokenRequest{
			RefreshToken: "refresh_token",
		}

		dbError := errors.New("db error")
		mockService.On(RefreshToken, mock.Anything, reqBody).Return(nil, dbError)

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, refreshTokenPath, bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.refreshTokenHandler(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		mockService.AssertExpectations(t)
	})
}

func TestLogoutUser(t *testing.T) {
	mockService := new(MockService)
	logger := zaptest.NewLogger(t).Sugar()
	LogoutUser := "LogoutUser"
	logoutPath := "/logout"

	t.Run("log user out", func(t *testing.T) {
		handler := NewHandler(mockService, logger)

		refreshToken := "refresh-token"

		mockService.On(LogoutUser, mock.Anything, refreshToken).Return(nil)

		req := httptest.NewRequest(http.MethodPost, "/"+refreshToken+logoutPath, bytes.NewReader(nil))
		w := httptest.NewRecorder()

		chiRC := chi.NewRouteContext()
		chiRC.URLParams.Add("refreshToken", refreshToken)

		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, chiRC))

		handler.logoutUserHandler(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("internal server error", func(t *testing.T) {
		mockService := new(MockService)
		logger := zaptest.NewLogger(t).Sugar()
		handler := NewHandler(mockService, logger)

		refreshToken := "refresh-token"

		mockService.On(LogoutUser, mock.Anything, refreshToken).Return(errors.New("dberror"))

		req := httptest.NewRequest(http.MethodPost, "/"+refreshToken+logoutPath, bytes.NewReader(nil))
		w := httptest.NewRecorder()

		chiRC := chi.NewRouteContext()
		chiRC.URLParams.Add("refreshToken", refreshToken)

		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, chiRC))

		handler.logoutUserHandler(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		mockService.AssertExpectations(t)
	})
}

func TestResendOTP(t *testing.T) {
	mockService := new(MockService)
	logger := zaptest.NewLogger(t).Sugar()
	ResendOTP := "ResendOTP"
	resendOtpPath := "/resendOTP"

	t.Run("resend otp", func(t *testing.T) {
		handler := NewHandler(mockService, logger)

		reqBody := userService.ResendOTPRequest{
			Email: "testResend@e.com",
		}
		responseBody := &userService.ResendOTPResponse{
			EmailID: "email_id",
		}
		mockService.On(ResendOTP, mock.Anything, reqBody).Return(responseBody, nil)

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, resendOtpPath, bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.resendOTPHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		mockService.AssertExpectations(t)
	})

	t.Run("passed unknown field to request", func(t *testing.T) {
		handler := NewHandler(mockService, logger)
		reqBody := struct {
			Email   string `json:"email" validate:"required,email,max=255"`
			Unknown string `json:"unknown"`
		}{
			"testResend2@e.com",
			"unknown",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, resendOtpPath, bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.resendOTPHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
		mockService.AssertExpectations(t)
		mockService.AssertNotCalled(t, ResendOTP)
	})

	t.Run("internal server error", func(t *testing.T) {
		mockService := new(MockService)
		logger := zaptest.NewLogger(t).Sugar()
		handler := NewHandler(mockService, logger)

		reqBody := userService.ResendOTPRequest{
			Email: "testResend3@e.com",
		}

		dbError := errors.New("otp provider failed to send otp")
		mockService.On(ResendOTP, mock.Anything, reqBody).Return(nil, dbError)

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, resendOtpPath, bytes.NewReader(body))
		w := httptest.NewRecorder()

		handler.resendOTPHandler(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		mockService.AssertExpectations(t)
	})
}
