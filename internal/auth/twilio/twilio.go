package twilio

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/twilio/twilio-go"
	verify "github.com/twilio/twilio-go/rest/verify/v2"
	"go.uber.org/zap"
)

var (
	ErrMaxRetriesExceeded = errors.New("max retries exceeded")
	ErrInvalidCode        = errors.New("invalid verification code")
)

const maxRetries = 3

type VerifyService interface {
	CreateVerification(serviceID string, params *verify.CreateVerificationParams) (*verify.VerifyV2Verification, error)
	CreateVerificationCheck(serviceID string, params *verify.CreateVerificationCheckParams) (*verify.VerifyV2VerificationCheck, error)
}

type TwilioVerification struct {
	verifyService VerifyService
	serviceID     string
	logger        *zap.SugaredLogger
}

func NewTwilioVerification(accountSID, authToken, serviceID string, logger *zap.SugaredLogger) *TwilioVerification {
	clientParam := twilio.ClientParams{
		Username: accountSID,
		Password: authToken,
	}
	client := twilio.NewRestClientWithParams(clientParam)
	return &TwilioVerification{verifyService: client.VerifyV2, serviceID: serviceID, logger: logger}
}

func (t *TwilioVerification) SendVerificationCode(email string) error {
	channelEmail := "email"
	params := &verify.CreateVerificationParams{
		To:      &email,
		Channel: &channelEmail,
	}
	lastErr := ""
	for i := range maxRetries {
		resp, err := t.verifyService.CreateVerification(t.serviceID, params)
		if err != nil {
			t.logger.Warn("failed to send verification code",
				zap.Int("attempt", i+1),
				zap.String("email", email),
				zap.Error(err))
			lastErr = err.Error()
			time.Sleep(time.Second * time.Duration(i+1) * 2)
			continue
		} else if resp.Sid != nil {
			return nil
		}
	}
	return fmt.Errorf("%w: %v", ErrMaxRetriesExceeded, lastErr)
}

func (t *TwilioVerification) VerifyCode(email, code string) error {
	params := &verify.CreateVerificationCheckParams{
		To:   &email,
		Code: &code,
	}
	for i := range maxRetries {
		resp, err := t.verifyService.CreateVerificationCheck(t.serviceID, params)
		if err != nil {
			t.logger.Warn("verification attempt failed",
				zap.Int("attempt", i+1),
				zap.String("email", email),
				zap.Error(err))
			log.Printf("failed to send email attempt %d of %d", i+1, maxRetries)
			log.Printf("error: %v", err.Error())

			time.Sleep(time.Second * time.Duration(i+1) * 2)
			continue
		} else if resp.Sid != nil {
			return nil
		}
	}

	return fmt.Errorf("%w: %v", ErrMaxRetriesExceeded, ErrInvalidCode)
}
