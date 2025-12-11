package auth

import "github.com/golang-jwt/jwt/v5"

type Authenticator interface {
	GenerateToken(claims jwt.Claims) (string, error)
	GenerateRefreshToken() (string, error)
	ValidateToken(token string) (*jwt.Token, error)
}

type OTPVerification interface {
	SendVerificationCode(email string) error
	VerifyCode(email, code string) error
}
