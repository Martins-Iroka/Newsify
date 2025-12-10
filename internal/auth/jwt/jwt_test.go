package jwt

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const secret = "u8Qw4v9J2k5s7x0zB2n4p6r8t1v3y5a7c9e0g2i4k6m8o0q2s"
const aud = "test-audience"
const iss = "test-issuer"

func TestJWTAuthenticatorGenerateToken(t *testing.T) {

	authenticator, err := NewJWTAuthenticator(secret, aud, iss)
	require.NoError(t, err)
	t.Run("should generate valid JWT token", func(t *testing.T) {
		claims := jwt.MapClaims{
			"sub": "user123",
			"exp": time.Now().Add(15 * time.Minute).Unix(),
			"iat": time.Now().Unix(),
			"aud": aud,
			"iss": iss,
		}

		token, err := authenticator.GenerateToken(claims)
		require.NoError(t, err)
		assert.NotEmpty(t, token)

		parsed, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
			return []byte(secret), nil
		})

		require.NoError(t, err)
		assert.True(t, parsed.Valid)
	})

	t.Run("should include custom claims in token", func(t *testing.T) {
		expectedUserID := "user456"
		expectedRole := "admin"

		claims := jwt.MapClaims{
			"sub":  expectedUserID,
			"role": expectedRole,
			"exp":  time.Now().Add(15 * time.Minute).Unix(),
			"iat":  time.Now().Unix(),
			"aud":  aud,
			"iss":  iss,
		}

		token, err := authenticator.GenerateToken(claims)
		require.NoError(t, err)

		parsed, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
			return []byte(secret), nil
		})
		require.NoError(t, err)

		mapClaims, ok := parsed.Claims.(jwt.MapClaims)
		require.True(t, ok)

		assert.Equal(t, expectedUserID, mapClaims["sub"])
		assert.Equal(t, expectedRole, mapClaims["role"])
	})
}

func TestJWTAuthenticatorValidateToken(t *testing.T) {
	authenticator, err := NewJWTAuthenticator(secret, aud, iss)
	require.NoError(t, err)

	t.Run("should validate valid token", func(t *testing.T) {
		claims := jwt.MapClaims{
			"sub": "user1",
			"exp": time.Now().Add(15 * time.Minute).Unix(),
			"iat": time.Now().Unix(),
			"aud": aud,
			"iss": iss,
		}

		token, err := authenticator.GenerateToken(claims)
		require.NoError(t, err)

		validatedToken, err := authenticator.ValidateToken(token)
		require.NoError(t, err)
		assert.True(t, validatedToken.Valid)
	})

	t.Run("should reject expired token", func(t *testing.T) {
		claims := jwt.MapClaims{
			"sub": "user2",
			"exp": time.Now().Add(-time.Hour).Unix(),
			"iat": time.Now().Add(-2 * time.Hour).Unix(),
			"aud": aud,
			"iss": iss,
		}

		token, err := authenticator.GenerateToken(claims)
		require.NoError(t, err)

		_, err = authenticator.ValidateToken(token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
	})

	t.Run("should reject token with wrong secret", func(t *testing.T) {
		wrongAuthenticator, err := NewJWTAuthenticator("wrong-secret", aud, iss)
		require.NoError(t, err)

		claims := jwt.MapClaims{
			"sub": "user3",
			"exp": time.Now().Add(15 * time.Minute).Unix(),
			"iat": time.Now().Unix(),
			"aud": aud,
			"iss": iss,
		}

		token, err := wrongAuthenticator.GenerateToken(claims)
		require.NoError(t, err)

		_, err = authenticator.ValidateToken(token)

		assert.Error(t, err)
	})

	t.Run("should reject token with wrong audience", func(t *testing.T) {
		claims := jwt.MapClaims{
			"sub": "user4",
			"exp": time.Now().Add(15 * time.Minute).Unix(),
			"iat": time.Now().Unix(),
			"aud": "wrong-audience",
			"iss": iss,
		}

		token, err := authenticator.GenerateToken(claims)
		require.NoError(t, err)

		_, err = authenticator.ValidateToken(token)

		assert.Error(t, err)
	})

	t.Run("should reject token with wrong issuer", func(t *testing.T) {
		claims := jwt.MapClaims{
			"sub": "user5",
			"exp": time.Now().Add(15 * time.Minute).Unix(),
			"iat": time.Now().Unix(),
			"aud": aud,
			"iss": "wrong-issuer",
		}

		token, err := authenticator.GenerateToken(claims)
		require.NoError(t, err)

		_, err = authenticator.ValidateToken(token)
		assert.Error(t, err)
	})

	t.Run("should reject malformed token", func(t *testing.T) {
		malformedToken := "not.a.valid.jwt.token"

		_, err := authenticator.ValidateToken(malformedToken)

		assert.Error(t, err)
	})

	t.Run("should reject token with no expiration", func(t *testing.T) {
		claims := jwt.MapClaims{
			"sub": "user6",
			"iat": time.Now().Unix(),
			"aud": aud,
			"iss": iss,
		}

		token, err := authenticator.GenerateToken(claims)
		require.NoError(t, err)

		_, err = authenticator.ValidateToken(token)

		assert.Error(t, err)
	})
}

func TestJWTAuthenticatorGenerateRefreshToken(t *testing.T) {
	authenticator, err := NewJWTAuthenticator(secret, aud, iss)
	require.NoError(t, err)
	t.Run("should generate refresh token", func(t *testing.T) {
		token, err := authenticator.GenerateRefreshToken()

		require.NoError(t, err)
		assert.NotEmpty(t, token)

		decoded, err := base64.URLEncoding.DecodeString(token)
		require.NoError(t, err)
		assert.Len(t, decoded, 32)
	})

	t.Run("should generate unique tokens", func(t *testing.T) {
		token1, err := authenticator.GenerateRefreshToken()
		require.NoError(t, err)

		token2, err := authenticator.GenerateRefreshToken()
		require.NoError(t, err)

		assert.NotEqual(t, token1, token2)
	})

	t.Run("should generate tokens of consistent length", func(t *testing.T) {
		token1, err := authenticator.GenerateRefreshToken()
		require.NoError(t, err)

		token2, err := authenticator.GenerateRefreshToken()
		require.NoError(t, err)

		assert.Equal(t, len(token1), len(token2))
	})
}

func TestJWTAuthenticatorRoundTrip(t *testing.T) {
	authenticator, err := NewJWTAuthenticator(secret, aud, iss)
	require.NoError(t, err)
	t.Run("should generate and validate token successfully", func(t *testing.T) {
		userID := "user8"
		claims := jwt.MapClaims{
			"sub": userID,
			"exp": time.Now().Add(1 * time.Hour).Unix(),
			"iat": time.Now().Unix(),
			"aud": aud,
			"iss": iss,
		}

		token, err := authenticator.GenerateToken(claims)
		require.NoError(t, err)

		validatedToken, err := authenticator.ValidateToken(token)
		require.NoError(t, err)
		assert.True(t, validatedToken.Valid)

		mapClaims, ok := validatedToken.Claims.(jwt.MapClaims)
		require.True(t, ok)
		assert.Equal(t, userID, mapClaims["sub"])
	})
}
