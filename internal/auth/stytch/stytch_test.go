package stytch

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stytchauth/stytch-go/v16/stytch/consumer/otp"
	"github.com/stytchauth/stytch-go/v16/stytch/consumer/otp/email"
	"go.uber.org/zap/zaptest"
)

type MockStytchOTPSendService struct {
	mock.Mock
}

type MockStytchOTPAuthService struct {
	mock.Mock
}

func (m *MockStytchOTPSendService) LoginOrCreate(ctx context.Context, params *email.LoginOrCreateParams) (*email.LoginOrCreateResponse, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*email.LoginOrCreateResponse), args.Error(1)
}

func (m *MockStytchOTPAuthService) Authenticate(ctx context.Context, params *otp.AuthenticateParams) (*otp.AuthenticateResponse, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*otp.AuthenticateResponse), args.Error(1)
}

func TestSendVerificationCode(t *testing.T) {
	userEmail := "test1@example.com"
	logger := zaptest.NewLogger(t).Sugar()
	const networkError = "network error"
	const LoginOrCreate = "LoginOrCreate"

	t.Run("should send verification code successfully", func(t *testing.T) {
		mockService := new(MockStytchOTPSendService)
		sv := &StytchVerification{
			logger:          logger,
			emailOTPService: mockService,
		}
		resp := &email.LoginOrCreateResponse{
			StatusCode: 200,
			EmailID:    "email_id_1",
		}
		mockService.On(LoginOrCreate, mock.Anything, mock.Anything).Return(resp, nil)

		emailId, err := sv.SendVerificationCode(userEmail)
		require.NoError(t, err)

		assert.Equal(t, resp.EmailID, emailId)
		mockService.AssertExpectations(t)

	})

	t.Run("should retry on failure and eventually succeed", func(t *testing.T) {
		mockService := new(MockStytchOTPSendService)
		sv := &StytchVerification{
			logger:          logger,
			emailOTPService: mockService,
		}

		resp := &email.LoginOrCreateResponse{
			StatusCode: 200,
			EmailID:    "email_id_1",
		}

		mockService.On(LoginOrCreate, mock.Anything, mock.Anything).Return(nil, errors.New(networkError)).Twice()

		mockService.On(LoginOrCreate, mock.Anything, mock.Anything).
			Return(resp, nil).Once()

		emailId, err := sv.SendVerificationCode(userEmail)
		require.NoError(t, err)
		assert.Equal(t, resp.EmailID, emailId)

		mockService.AssertExpectations(t)
	})

	t.Run("should fail after max retries", func(t *testing.T) {
		mockService := new(MockStytchOTPSendService)
		sv := &StytchVerification{
			logger:          logger,
			emailOTPService: mockService,
		}

		mockService.On(LoginOrCreate, mock.Anything, mock.Anything).
			Return(nil, errors.New(networkError)).Times(maxRetries)

		emailId, err := sv.SendVerificationCode(userEmail)
		require.Empty(t, emailId)
		require.Error(t, err)
		assert.Contains(t, err.Error(), ErrMaxRetriesExceeded.Error())

		mockService.AssertExpectations(t)
		mockService.AssertNumberOfCalls(t, LoginOrCreate, maxRetries)
	})

	t.Run("should handle status code not equal to 200", func(t *testing.T) {
		mockService := new(MockStytchOTPSendService)
		sv := &StytchVerification{
			logger:          logger,
			emailOTPService: mockService,
		}

		mockService.On(LoginOrCreate, mock.Anything, mock.Anything).Return(
			&email.LoginOrCreateResponse{StatusCode: 400}, nil,
		)

		emailID, err := sv.SendVerificationCode(userEmail)
		require.Empty(t, emailID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "400")

		mockService.AssertExpectations(t)
	})
}

func TestVerifyCode(t *testing.T) {
	emailID := "email_id_1"
	code := "123456"
	logger := zaptest.NewLogger(t).Sugar()
	const Authenticate = "Authenticate"
	const networkError = "network error"

	t.Run("should verify code successfully", func(t *testing.T) {
		mockService := new(MockStytchOTPAuthService)
		sv := &StytchVerification{
			logger:                 logger,
			stytchOTPAuthenticator: mockService,
		}

		resp := &otp.AuthenticateResponse{StatusCode: 200}

		mockService.On(Authenticate, mock.Anything, mock.Anything).Return(resp, nil)
		err := sv.VerifyCode(emailID, code)
		assert.NoError(t, err)

		mockService.AssertExpectations(t)
	})

	t.Run("should retry on failure", func(t *testing.T) {
		mockService := new(MockStytchOTPAuthService)
		sv := &StytchVerification{
			logger:                 logger,
			stytchOTPAuthenticator: mockService,
		}

		mockService.On(Authenticate, mock.Anything, mock.Anything).
			Return(nil, errors.New(networkError)).Twice()

		mockService.On(Authenticate, mock.Anything, mock.Anything).
			Return(&otp.AuthenticateResponse{StatusCode: 200}, nil).Once()

		err := sv.VerifyCode(emailID, code)
		assert.NoError(t, err)

		mockService.AssertExpectations(t)
		mockService.AssertNumberOfCalls(t, Authenticate, 3)
	})

	t.Run("should fail after max retries", func(t *testing.T) {
		mockService := new(MockStytchOTPAuthService)
		sv := &StytchVerification{
			logger:                 logger,
			stytchOTPAuthenticator: mockService,
		}

		mockService.On(Authenticate, mock.Anything, mock.Anything).Return(nil, errors.New(networkError)).Times(maxRetries)

		err := sv.VerifyCode(emailID, code)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "3")

		mockService.AssertExpectations(t)
		mockService.AssertNumberOfCalls(t, Authenticate, maxRetries)
	})

	t.Run("should handle status code not equal to 200", func(t *testing.T) {
		mockService := new(MockStytchOTPAuthService)
		sv := &StytchVerification{
			logger:                 logger,
			stytchOTPAuthenticator: mockService,
		}

		mockService.On(Authenticate, mock.Anything, mock.Anything).Return(&otp.AuthenticateResponse{StatusCode: 400}, nil)

		err := sv.VerifyCode(emailID, code)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "400")

		mockService.AssertExpectations(t)
	})

}
