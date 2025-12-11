package password

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const password = "password"

func TestHashPassword(t *testing.T) {
	t.Run("should successfully hash a password", func(t *testing.T) {
		hash, err := HashPassword(password)
		require.NoError(t, err)
		assert.NotEmpty(t, hash)
		assert.NotEqual(t, password, hash)
	})

	t.Run("should throw error on password exceeding 72 bytes", func(t *testing.T) {
		longPassword := strings.Repeat("a", 73)
		_, err := HashPassword(longPassword)
		require.Error(t, err, "expected error for password > 72 bytes")
		assert.Contains(t, err.Error(), "password must not exceed 72 bytes (bcrypt limitation)")
	})
}

func TestComparePasswords(t *testing.T) {
	t.Run("should verify correct password against hash", func(t *testing.T) {
		hash, err := HashPassword(password)
		require.NoError(t, err)
		require.NoError(t, err)

		err = ComparePasswords(hash, password)
		require.NoError(t, err)
	})

	t.Run("should not match wrong password", func(t *testing.T) {
		wrongPassword := "wrong-password"
		hash, err := HashPassword(password)
		require.NoError(t, err)

		err = ComparePasswords(hash, wrongPassword)
		require.Error(t, err)
	})

	t.Run("should handle special characters and unicode", func(t *testing.T) {
		testCases := []string{
			"P@ssw0rd!#$%^&*()", // Symbols
			"pässwörd🔐中文",       // Unicode/Emoji
			"   spaces   ",      // Leading/trailing spaces
			"tab\tnewline\n",    // Control characters
		}

		for _, tc := range testCases {
			hash, err := HashPassword(tc)
			require.NoError(t, err)

			err = ComparePasswords(hash, tc)
			require.NoError(t, err)

			err = ComparePasswords(hash, tc+"!")
			require.Error(t, err)
		}
	})

	t.Run("should handle invalid hash inputs gracefully", func(t *testing.T) {
		err := ComparePasswords("not-a-hash", password)
		require.Error(t, err)

		err = ComparePasswords("", password)
		require.Error(t, err)
	})
}
