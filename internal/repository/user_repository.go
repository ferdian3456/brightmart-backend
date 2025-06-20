package repository

import (
	"brightmart-backend/internal/model"
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"time"
)

type UserRepository struct {
	Log     *zap.Logger
	DB      *pgxpool.Pool
	DBCache *redis.ClusterClient
}

func NewUserRepository(zap *zap.Logger, db *pgxpool.Pool, dbCache *redis.ClusterClient) *UserRepository {
	return &UserRepository{
		Log:     zap,
		DB:      db,
		DBCache: dbCache,
	}
}

func (repository *UserRepository) Register(ctx context.Context, tx pgx.Tx, user model.User) {
	query := "INSERT INTO users (id,username,email,password,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6)"
	_, err := tx.Exec(ctx, query, user.Id, user.Username, user.Email, user.Password, user.Created_at, user.Updated_at)
	if err != nil {
		repository.Log.Panic("failed to query into database", zap.Error(err))
	}
}

func (repository *UserRepository) RegisterViaOAuth(ctx context.Context, tx pgx.Tx, user model.User) {
	query := "INSERT INTO users (id,username,email,profile_picture,auth_provider,provider_user_id,is_verified,password,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)"
	_, err := tx.Exec(ctx, query, user.Id, user.Username, user.Email, user.Profile_picture, user.Auth_provider, user.Provider_user_id, user.Is_verified, user.Password, user.Created_at, user.Updated_at)
	if err != nil {
		repository.Log.Panic("failed to query into database", zap.Error(err))
	}
}

func (repository *UserRepository) SaveUserInCache(ctx context.Context, email string, hashedCode string) {
	key := "verify:" + email
	err := repository.DBCache.Set(ctx, key, hashedCode, 10*time.Minute).Err()
	if err != nil {
		repository.Log.Panic("failed to set into cache database", zap.Error(err))
	}
}

func (repository *UserRepository) SaveUserStateInCache(ctx context.Context, state string) {
	key := "oauth:state:" + state
	err := repository.DBCache.Set(ctx, key, state, 10*time.Minute).Err()
	if err != nil {
		repository.Log.Panic("failed to set into cache database", zap.Error(err))
	}
}

func (repository *UserRepository) CheckUserStateExistenceInCache(ctx context.Context, state string) error {
	key := "oauth:state:" + state

	_, err := repository.DBCache.Get(ctx, key).Result()
	if err == redis.Nil {
		return errors.New("state does not exist or has expired")
	} else if err != nil {
		repository.Log.Panic("failed to get from cache database", zap.Error(err))
		return err
	}

	return nil
}

func (repository *UserRepository) DeleteUserStateInCache(ctx context.Context, state string) {
	key := "oauth:state:" + state

	err := repository.DBCache.Del(ctx, key).Err()
	if err != nil {
		repository.Log.Error("failed to delete used state from cache", zap.Error(err))
	}
}

func (repository *UserRepository) FindUserCodeByEmailInCache(ctx context.Context, email string) (string, error) {
	key := "verify:" + email
	hashedCode, err := repository.DBCache.Get(ctx, key).Result()
	if err == redis.Nil {
		return "", errors.New("code expired or not found")
	} else if err != nil {
		repository.Log.Panic("failed to get from cache database", zap.Error(err))
	}

	return hashedCode, nil
}

func (repository *UserRepository) UpdateUserStatus(ctx context.Context, tx pgx.Tx, email string, status bool, updated_at time.Time) {
	query := `
		UPDATE users 
		SET is_verified = $2, updated_at = $3 
		WHERE email = $1
	`
	_, err := tx.Exec(ctx, query, email, status, updated_at)
	if err != nil {
		repository.Log.Panic("failed to query into database", zap.Error(err))
	}
}

func (repository *UserRepository) UpdateProviderUserID(ctx context.Context, tx pgx.Tx, id string, email string, updated_at time.Time) {
	query := `
		UPDATE users 
		SET provider_user_id = $2, updated_at = $3 
		WHERE email = $1
	`
	_, err := tx.Exec(ctx, query, email, id, updated_at)
	if err != nil {
		repository.Log.Panic("failed to query into database", zap.Error(err))
	}
}

func (repository *UserRepository) DeleteUserCodeInCache(ctx context.Context, email string) {
	key := "verify:" + email
	err := repository.DBCache.Del(ctx, key).Err()
	if err != nil {
		repository.Log.Panic("failed to delete verification code from cache", zap.Error(err))
	}
}

func (repository *UserRepository) CheckUsernameUnique(ctx context.Context, tx pgx.Tx, username string) error {
	query := "SELECT username FROM users WHERE username=$1 LIMIT 1"

	var existingUsername string
	err := tx.QueryRow(ctx, query, username).Scan(&existingUsername)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		repository.Log.Panic("failed to query database", zap.Error(err))
	}

	return errors.New("username already exist")
}

func (repository *UserRepository) CheckEmailUnique(ctx context.Context, tx pgx.Tx, email string) error {
	query := "SELECT email FROM users WHERE email=$1 LIMIT 1"

	var existingEmail string
	err := tx.QueryRow(ctx, query, email).Scan(&existingEmail)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		repository.Log.Panic("failed to query database", zap.Error(err))
	}

	return errors.New("email already exist")
}

func (repository *UserRepository) FindUserIdByEmail(ctx context.Context, tx pgx.Tx, email string) (string, error) {
	query := "SELECT id FROM users WHERE email=$1 AND is_verified=true LIMIT 1"

	var id string
	err := tx.QueryRow(ctx, query, email).Scan(&id)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", errors.New("user not found")
		}

		repository.Log.Panic("failed to query database", zap.Error(err))
	}

	return id, nil
}

func (repository *UserRepository) FindNotVerifiedUserIdByEmail(ctx context.Context, tx pgx.Tx, email string) (string, error) {
	query := "SELECT id FROM users WHERE email=$1 AND is_verified=false LIMIT 1"

	var id string
	err := tx.QueryRow(ctx, query, email).Scan(&id)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", errors.New("user not found")
		}

		repository.Log.Panic("failed to query database", zap.Error(err))
	}

	return id, nil
}

func (repository *UserRepository) FindUsenamedByEmail(ctx context.Context, tx pgx.Tx, email string) (string, error) {
	query := "SELECT username FROM users WHERE email=$1 AND is_verified=false LIMIT 1"

	var username string
	err := tx.QueryRow(ctx, query, email).Scan(&username)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", errors.New("user not found")
		}
		repository.Log.Panic("failed to query database", zap.Error(err))
	}

	return username, nil
}

func (repository *UserRepository) AddRefreshTokenWithTx(ctx context.Context, tx pgx.Tx, refreshtoken model.RefreshToken) {
	query := "INSERT INTO refresh_tokens (user_id,hashed_refresh_token,created_at,expired_at) VALUES ($1,$2,$3,$4)"
	_, err := tx.Exec(ctx, query, refreshtoken.User_id, refreshtoken.Hashed_refresh_token, refreshtoken.Created_at, refreshtoken.Expired_at)
	if err != nil {
		repository.Log.Panic("failed to query into database", zap.Error(err))
	}
}

func (repository *UserRepository) UpdateRefreshTokenWithTx(ctx context.Context, tx pgx.Tx, tokenStatus string, userUUID string) {
	query := "UPDATE refresh_tokens SET status = $1 WHERE user_id = $2 AND created_at = (SELECT MAX(created_at) FROM refresh_tokens WHERE user_id = $2)"
	_, err := tx.Exec(ctx, query, tokenStatus, userUUID)
	if err != nil {
		repository.Log.Panic("failed to query into database", zap.Error(err))
	}
}

func (repository *UserRepository) FindLatestRefreshToken(ctx context.Context, tx pgx.Tx) (string, error) {
	query := "SELECT hashed_refresh_token FROM refresh_tokens ORDER BY created_at DESC LIMIT 1"

	var hashedRefreshToken string
	err := tx.QueryRow(ctx, query).Scan(&hashedRefreshToken)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", errors.New("refresh token not found")
		}
		repository.Log.Panic("failed to query database", zap.Error(err))
	}

	return hashedRefreshToken, nil
}

func (repository *UserRepository) Login(ctx context.Context, tx pgx.Tx, email string) (model.User, error) {
	query := "SELECT id,email,password FROM users WHERE email=$1"

	var user model.User
	err := tx.QueryRow(ctx, query, email).Scan(&user.Id, &user.Email, &user.Password)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return user, errors.New("user not found")
		}
		repository.Log.Panic("failed to query database", zap.Error(err))
	}

	return user, nil
}

func (repository *UserRepository) FindByProviderUserID(ctx context.Context, tx pgx.Tx, id string) (model.User, error) {
	query := "SELECT id,email FROM users WHERE provider_user_id=$1"

	user := model.User{}
	err := repository.DB.QueryRow(ctx, query, id).Scan(&user.Id, &user.Email)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return user, errors.New("user not found")
		}
		repository.Log.Panic("failed to query database", zap.Error(err))
	}

	return user, nil
}

func (repository *UserRepository) CheckUserExistence(ctx context.Context, userUUID string) error {
	query := "SELECT username FROM users WHERE id=$1"

	var username string
	err := repository.DB.QueryRow(ctx, query, userUUID).Scan(&username)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errors.New("user already exist")
		}
		repository.Log.Panic("failed to query database", zap.Error(err))
	}

	return nil
}

func (repository *UserRepository) CheckUserExistenceWithTx(ctx context.Context, tx pgx.Tx, userUUID string) error {
	query := "SELECT username FROM users WHERE id=$1"

	var username string
	err := tx.QueryRow(ctx, query, userUUID).Scan(&username)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errors.New("user not found")
		}
		repository.Log.Panic("failed to query database", zap.Error(err))
	}

	return nil
}
