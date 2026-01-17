package twilio

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	verify "github.com/twilio/twilio-go/rest/verify/v2"
	"go.uber.org/zap/zaptest"
)

type MockVerifyService struct {
	mock.Mock
}

func (m *MockVerifyService) CreateVerification(serviceID string, params *verify.CreateVerificationParams) (*verify.VerifyV2Verification, error) {
	args := m.Called(serviceID, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*verify.VerifyV2Verification), args.Error(1)
}

func (m *MockVerifyService) CreateVerificationCheck(serviceID string, params *verify.CreateVerificationCheckParams) (*verify.VerifyV2VerificationCheck, error) {
	args := m.Called(serviceID, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*verify.VerifyV2VerificationCheck), args.Error(1)
}

func TestSendVerificationCode(t *testing.T) {
	serviceID := "test-service-id"
	email := "test@example.com"
	const networkError = "network error"
	const createVerification = "CreateVerification"

	t.Run("should send verification code successfully", func(t *testing.T) {
		mockService := new(MockVerifyService)
		logger := zaptest.NewLogger(t).Sugar()
		tv := &TwilioVerification{
			verifyService: mockService,
			serviceID:     serviceID,
			logger:        logger,
		}

		sid := "verification-sid-123"
		mockService.On(createVerification, serviceID, mock.Anything).Return(&verify.VerifyV2Verification{Sid: &sid}, nil)

		_, err := tv.SendVerificationCode(email)
		assert.NoError(t, err)
		mockService.AssertExpectations(t)

	})

	t.Run("should retry on failure and eventually succeed", func(t *testing.T) {
		mockService := new(MockVerifyService)
		logger := zaptest.NewLogger(t).Sugar()
		tv := &TwilioVerification{
			verifyService: mockService,
			serviceID:     serviceID,
			logger:        logger,
		}

		mockService.On(createVerification, serviceID, mock.Anything).Return(nil, errors.New(networkError)).Once()

		mockService.On(createVerification, serviceID, mock.Anything).Return(nil, errors.New(networkError)).Once()

		sid := "verification-sid-123"
		mockService.On(createVerification, serviceID, mock.Anything).
			Return(&verify.VerifyV2Verification{Sid: &sid}, nil).Once()

		_, err := tv.SendVerificationCode(email)
		assert.NoError(t, err)
		mockService.AssertNumberOfCalls(t, createVerification, 3)
	})

	t.Run("should fail after max retries", func(t *testing.T) {
		mockService := new(MockVerifyService)
		logger := zaptest.NewLogger(t).Sugar()
		tv := &TwilioVerification{
			verifyService: mockService,
			serviceID:     serviceID,
			logger:        logger,
		}

		mockService.On(createVerification, serviceID, mock.Anything).
			Return(nil, errors.New("persistent error")).Times(maxRetries)

		_, err := tv.SendVerificationCode(email)
		require.Error(t, err)
		assert.Contains(t, err.Error(), ErrMaxRetriesExceeded.Error())

		mockService.AssertNumberOfCalls(t, createVerification, maxRetries)
	})

	t.Run("should handle nil sid response", func(t *testing.T) {
		mockService := new(MockVerifyService)
		logger := zaptest.NewLogger(t).Sugar()
		tv := &TwilioVerification{
			verifyService: mockService,
			serviceID:     serviceID,
			logger:        logger,
		}

		mockService.On(createVerification, serviceID, mock.Anything).
			Return(&verify.VerifyV2Verification{Sid: nil}, nil).Times(maxRetries)

		_, err := tv.SendVerificationCode(email)
		assert.Error(t, err)

		mockService.AssertNumberOfCalls(t, createVerification, maxRetries)
	})
}

func TestVerifyCode(t *testing.T) {
	serviceID := "test-service-id"
	email := "test@example.com"
	code := "123456"
	sid := "check-sid-123"
	const createVerificationCheck = "CreateVerificationCheck"

	t.Run("should verify code successfully", func(t *testing.T) {
		mockService := new(MockVerifyService)
		logger := zaptest.NewLogger(t).Sugar()
		tv := &TwilioVerification{
			verifyService: mockService,
			serviceID:     serviceID,
			logger:        logger,
		}

		mockService.On(createVerificationCheck, serviceID, mock.Anything).
			Return(&verify.VerifyV2VerificationCheck{Sid: &sid}, nil)

		err := tv.VerifyCode(email, code)
		assert.NoError(t, err)
		mockService.AssertExpectations(t)
	})

	t.Run("should retry on failure", func(t *testing.T) {
		mockService := new(MockVerifyService)
		logger := zaptest.NewLogger(t).Sugar()
		tv := &TwilioVerification{
			verifyService: mockService,
			serviceID:     serviceID,
			logger:        logger,
		}

		mockService.On(createVerificationCheck, serviceID, mock.Anything).Return(nil, errors.New("network error")).Once()

		mockService.On(createVerificationCheck, serviceID, mock.Anything).
			Return(&verify.VerifyV2VerificationCheck{Sid: &sid}, nil).Once()

		err := tv.VerifyCode(email, code)
		assert.NoError(t, err)
		mockService.AssertNumberOfCalls(t, createVerificationCheck, 2)
	})

	t.Run("should fail after max retries", func(t *testing.T) {
		mockService := new(MockVerifyService)
		logger := zaptest.NewLogger(t).Sugar()
		tv := &TwilioVerification{
			verifyService: mockService,
			serviceID:     serviceID,
			logger:        logger,
		}

		mockService.On(createVerificationCheck, serviceID, mock.Anything).Return(nil, errors.New("invalid code")).Times(maxRetries)

		err := tv.VerifyCode(email, code)
		assert.Error(t, err)
		mockService.AssertNumberOfCalls(t, createVerificationCheck, maxRetries)
	})
}
