package user

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"time"

	"com.martdev.newsify/internal/util"
)

type User struct {
	ID         int64
	Username   string
	Email      string
	Password   string
	IsVerified bool
	CreatedAt  string
}

type UserStore struct {
	DB *sql.DB
}

func (u *UserStore) ActivateUser(ctx context.Context, token string) error {
	return util.WithTransaction(u.DB, ctx, func(tx *sql.Tx) error {
		user, err := u.getUserByVerificationToken(ctx, tx, token)
		if err != nil {
			return nil
		}

		if err := u.updateUser(ctx, tx, user); err != nil {
			return err
		}

		if err := u.deleteUserVerificationToken(ctx, tx, user.ID); err != nil {
			return err
		}

		return nil
	})
}

func (u *UserStore) CreateUserAndVerificationToken(ctx context.Context, user *User, token string) error {
	return nil
}

func (u *UserStore) CreateRefreshToken(ctx context.Context, userID int64, tokenHash string, expiresAt time.Time) error {
	return nil
}

func (u *UserStore) DeleteExpiredRefreshTokens(ctx context.Context) error {
	return nil
}

func (u *UserStore) DeleteUser(ctx context.Context, userID int64) error {
	return nil
}

func (u *UserStore) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	return nil, nil
}

func (u *UserStore) GetUserByID(ctx context.Context, userID int64) (*User, error) {
	return nil, nil
}

func (u *UserStore) GetUserByRefreshToken(ctx context.Context, tokenHash string) (*User, error) {
	return nil, nil
}

func (u *UserStore) RevokeRefreshToken(ctx context.Context, tokenHash string) error {
	return nil
}

func (u *UserStore) getUserByVerificationToken(ctx context.Context, tx *sql.Tx, token string) (*User, error) {
	query := `
		SELECT u.id FROM users u JOIN users_verification_tracking uv ON u.id = uv.user_id WHERE uv.token = $1
	`
	hash := sha256.Sum256([]byte(token))
	hashToken := hex.EncodeToString(hash[:])

	ctx, cancel := context.WithTimeout(ctx, util.QueryTimeoutDuration)
	defer cancel()

	var user User
	if err := tx.QueryRowContext(ctx, query, hashToken).Scan(
		&user.ID,
	); err != nil {
		switch err {
		case sql.ErrNoRows:
			return nil, util.ErrorNotFound
		default:
			return nil, err
		}
	}

	return &user, nil
}

func (u *UserStore) updateUser(ctx context.Context, tx *sql.Tx, user *User) error {
	query := `
		UPDATE users SET is_verified = $1 WHERE id = $2
	`

	user.IsVerified = true

	ctx, cancel := context.WithTimeout(ctx, util.QueryTimeoutDuration)
	defer cancel()

	_, err := tx.ExecContext(ctx, query, user.IsVerified, user.ID)
	if err != nil {
		return err
	}
	return nil
}

func (u *UserStore) deleteUserVerificationToken(ctx context.Context, tx *sql.Tx, userID int64) error {
	query := `
		DELETE FROM users_verification_tracking WHERE user_id = $1
	`

	ctx, cancel := context.WithTimeout(ctx, util.QueryTimeoutDuration)
	defer cancel()

	_, err := tx.ExecContext(ctx, query, userID)
	if err != nil {
		return err
	}

	return nil
}
