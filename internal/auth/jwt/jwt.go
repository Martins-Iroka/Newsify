package jwt

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

type JWTAuthenticator struct {
	secret string
	aud    string
	iss    string
}

func NewJWTAuthenticator(secret, aud, iss string) (*JWTAuthenticator, error) {
	if secret == "" {
		return nil, fmt.Errorf("jwt: secret must not be empty")
	}
	if aud == "" {
		return nil, fmt.Errorf("jwt: audience must not be empty")
	}
	if iss == "" {
		return nil, fmt.Errorf("jwt: issuer must not be empty")
	}
	return &JWTAuthenticator{
		secret: secret,
		aud:    aud,
		iss:    iss,
	}, nil
}

func (j *JWTAuthenticator) GenerateToken(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(j.secret))
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT token: %w", err)
	}

	return tokenString, nil
}

func (j *JWTAuthenticator) GenerateRefreshToken() (string, error) {
	token := make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		return "", fmt.Errorf("failed to generate random refresh token: %w", err)
	}
	return base64.URLEncoding.EncodeToString(token), nil
}

func (j *JWTAuthenticator) ValidateToken(token string) (*jwt.Token, error) {
	return jwt.Parse(token, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}
		return []byte(j.secret), nil
	}, jwt.WithExpirationRequired(),
		jwt.WithAudience(j.aud),
		jwt.WithIssuer(j.iss),
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}))
}
