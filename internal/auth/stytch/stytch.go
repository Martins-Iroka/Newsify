package stytch

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/stytchauth/stytch-go/v16/stytch/consumer/otp"
	"github.com/stytchauth/stytch-go/v16/stytch/consumer/otp/email"
	"github.com/stytchauth/stytch-go/v16/stytch/consumer/stytchapi"
	"go.uber.org/zap"
)

var (
	ErrMaxRetriesExceeded = errors.New("max retries exceeded")
	ErrInvalidCode        = errors.New("invalid verification code")
)

const maxRetries = 3

type StytchEmailOTPService interface {
	LoginOrCreate(context.Context, *email.LoginOrCreateParams) (*email.LoginOrCreateResponse, error)
}

type StytchOTPAuthService interface {
	Authenticate(context.Context, *otp.AuthenticateParams) (*otp.AuthenticateResponse, error)
}

// integrate this in main in place of twilo
type StytchVerification struct {
	logger                 *zap.SugaredLogger
	emailOTPService        StytchEmailOTPService
	stytchOTPAuthenticator StytchOTPAuthService
}

func NewStytchVerification(projectID, secret string, logger *zap.SugaredLogger) (*StytchVerification, error) {
	client, err := stytchapi.NewClient(projectID, secret)
	if err != nil {
		return nil, err
	}
	return &StytchVerification{logger: logger, emailOTPService: client.OTPs.Email, stytchOTPAuthenticator: client.OTPs}, nil
}

func (sv *StytchVerification) SendVerificationCode(userEmail string) (string, error) {
	params := &email.LoginOrCreateParams{
		Email:             userEmail,
		ExpirationMinutes: 5,
	}

	lastErr := ""
	for i := range maxRetries {
		resp, err := sv.emailOTPService.LoginOrCreate(context.Background(), params)
		if err != nil {
			sv.logger.Warn("failed to send verification code",
				zap.Int("attempt", i+1),
				zap.String("email", userEmail),
				zap.Error(err))
			lastErr = err.Error()
			time.Sleep(time.Second * time.Duration(i+1) * 2)
			continue
		} else if resp.StatusCode != 200 {
			return "", fmt.Errorf("error sending OTP. status code is %d", resp.StatusCode)
		} else {
			return resp.EmailID, nil
		}
	}

	return "", fmt.Errorf("%w: %v", ErrMaxRetriesExceeded, lastErr)
}

func (sv *StytchVerification) VerifyCode(emailId, code string) error {
	params := &otp.AuthenticateParams{
		MethodID:               emailId,
		Code:                   code,
		SessionDurationMinutes: 60,
	}
	for i := range maxRetries {
		resp, err := sv.stytchOTPAuthenticator.Authenticate(context.Background(), params)
		if err != nil {
			sv.logger.Warn("verification attempt failed",
				zap.Int("attempt", i+1),
				zap.String("emailID", emailId),
				zap.Error(err))

			time.Sleep(time.Second * time.Duration(i+1) * 2)
			continue
		} else if resp.StatusCode != 200 {
			return fmt.Errorf("error verifying OTP. status code is %d", resp.StatusCode)
		} else {
			return nil
		}
	}

	return fmt.Errorf("failed to verify code after %d attempts", maxRetries)
}
