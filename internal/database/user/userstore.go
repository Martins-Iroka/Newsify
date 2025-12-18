package user

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"time"

	"com.martdev.newsify/internal/util"
)

type UserStorer interface {
	ActivateUser(ctx context.Context, token string) error
	CreateUserAndVerificationToken(ctx context.Context, user *User, token string) error
	CreateRefreshToken(ctx context.Context, userID int64, tokenHash string, expiresAt time.Time) error
	DeleteExpiredRefreshTokens(context.Context) error
	DeleteUser(ctx context.Context, userID int64) error
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	GetUserByID(ctx context.Context, userID int64) (*User, error)
	GetUserByRefreshToken(ctx context.Context, tokenHash string) (*User, error)
	RevokeRefreshToken(ctx context.Context, tokenHash string) error
}
type User struct {
	ID         int64
	Username   string
	Email      string
	Password   string
	IsVerified bool
	CreatedAt  string
	Role       string
}

type UserStore struct {
	DB *sql.DB
}

func (u *UserStore) ActivateUser(ctx context.Context, token string) error {
	return util.WithTransaction(u.DB, ctx, func(tx *sql.Tx) error {
		user, err := u.getUserByVerificationToken(ctx, tx, token)
		if err != nil {
			return err
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
	return util.WithTransaction(u.DB, ctx, func(tx *sql.Tx) error {
		if err := u.createUser(ctx, tx, user); err != nil {
			return err
		}

		if err := u.createUserVerificationToken(ctx, tx, token, user.ID); err != nil {
			return err
		}

		return nil
	})
}

func (u *UserStore) CreateRefreshToken(ctx context.Context, userID int64, tokenHash string, expiresAt time.Time) error {
	query := `
		INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)
	`
	ctx, cancel := context.WithTimeout(ctx, util.QueryTimeoutDuration)
	defer cancel()

	_, err := u.DB.ExecContext(ctx, query, userID, tokenHash, expiresAt)
	return err
}

func (u *UserStore) DeleteExpiredRefreshTokens(ctx context.Context) error {
	query := `
		DELETE FROM refresh_tokens WHERE expires_at < NOW() OR revoked = TRUE
	`

	ctx, cancel := context.WithTimeout(ctx, util.QueryTimeoutDuration)
	defer cancel()

	_, err := u.DB.ExecContext(ctx, query)

	return err
}

func (u *UserStore) DeleteUser(ctx context.Context, userID int64) error {
	return util.WithTransaction(u.DB, ctx, func(tx *sql.Tx) error {
		if err := u.deleteUser(ctx, tx, userID); err != nil {
			return err
		}

		if err := u.deleteUserVerificationToken(ctx, tx, userID); err != nil {
			return err
		}

		return nil
	})
}

func (u *UserStore) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	query := `
		SELECT id, password, role FROM users WHERE email = $1 AND is_verified = true
	`
	ctx, cancel := context.WithTimeout(ctx, util.QueryTimeoutDuration)
	defer cancel()

	var user User

	if err := u.DB.QueryRowContext(ctx, query, email).Scan(
		&user.ID,
		&user.Password,
		&user.Role,
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

func (u *UserStore) GetUserByID(ctx context.Context, userID int64) (*User, error) {
	query := `SELECT id, username, email, role FROM users u WHERE u.id = $1`

	ctx, cancel := context.WithTimeout(ctx, util.QueryTimeoutDuration)
	defer cancel()

	var user User
	if err := u.DB.QueryRowContext(ctx, query, userID).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.Role,
	); err != nil {
		return nil, err
	}

	return &user, nil
}

func (u *UserStore) GetUserByRefreshToken(ctx context.Context, tokenHash string) (*User, error) {
	query := `
		SELECT u.id FROM users u INNER JOIN refresh_tokens rt ON u.id = rt.user_id
		WHERE rt.token_hash = $1 AND rt.expires_at > NOW() AND rt.revoked = false
	`
	ctx, cancel := context.WithTimeout(ctx, util.QueryTimeoutDuration)
	defer cancel()

	var user User
	if err := u.DB.QueryRowContext(ctx, query, tokenHash).Scan(
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

func (u *UserStore) RevokeRefreshToken(ctx context.Context, tokenHash string) error {
	query := `UPDATE refresh_tokens SET revoked = TRUE WHERE token_hash = $1`

	ctx, cancel := context.WithTimeout(ctx, util.QueryTimeoutDuration)
	defer cancel()

	_, err := u.DB.ExecContext(ctx, query, tokenHash)
	return err
}

func (u *UserStore) createUser(ctx context.Context, tx *sql.Tx, user *User) error {
	query := `
		INSERT INTO users (email, username, password, role) VALUES ($1, $2, $3) RETURNING id
	`
	ctx, cancel := context.WithTimeout(ctx, util.QueryTimeoutDuration)
	defer cancel()

	if err := tx.QueryRowContext(ctx, query, user.Email, user.Username, user.Password, user.Role).Scan(
		&user.ID,
	); err != nil {
		switch {
		case err.Error() == `pq: duplicate key value violates unique constraint "users_email_key"`:
			return util.ErrorDuplicateEmail
		case err.Error() == `pq: duplicate key value violates unique constraint "users_username_key"`:
			return util.ErrorDuplicateUsername
		default:
			return err
		}
	}
	return nil
}

func (u *UserStore) createUserVerificationToken(ctx context.Context, tx *sql.Tx, token string, userID int64) error {
	query := `INSERT INTO users_verification_tracking (token, user_id) VALUES ($1, $2)`

	ctx, cancel := context.WithTimeout(ctx, util.QueryTimeoutDuration)
	defer cancel()

	hash := sha256.Sum256([]byte(token))
	hashToken := hex.EncodeToString(hash[:])
	_, err := tx.ExecContext(ctx, query, hashToken, userID)
	if err != nil {
		return err
	}

	return nil
}

func (u *UserStore) deleteUser(ctx context.Context, tx *sql.Tx, userID int64) error {
	query := `DELETE FROM users WHERE id = $1`

	ctx, cancel := context.WithTimeout(ctx, util.QueryTimeoutDuration)
	defer cancel()

	_, err := tx.ExecContext(ctx, query, userID)
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
