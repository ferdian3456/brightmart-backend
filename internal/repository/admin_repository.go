package repository

import (
	"brightmart-backend/internal/model"
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

type AdminRepository struct {
	Log     *zap.Logger
	DB      *pgxpool.Pool
	DBCache *redis.ClusterClient
}

func NewAdminRepository(zap *zap.Logger, db *pgxpool.Pool, dbCache *redis.ClusterClient) *AdminRepository {
	return &AdminRepository{
		Log:     zap,
		DB:      db,
		DBCache: dbCache,
	}
}

func (repository *AdminRepository) Login(ctx context.Context, tx pgx.Tx, email string) (model.Admin, error) {
	query := "SELECT id,email,password FROM admins WHERE email=$1"

	var admin model.Admin
	err := tx.QueryRow(ctx, query, email).Scan(&admin.Id, &admin.Email, &admin.Password)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return admin, errors.New("admin not found")
		}
		repository.Log.Panic("failed to query database", zap.Error(err))
	}

	return admin, nil
}

func (repository *AdminRepository) AddRefreshTokenWithTx(ctx context.Context, tx pgx.Tx, refreshtoken model.RefreshToken) {
	query := "INSERT INTO admin_refresh_tokens (user_id,hashed_refresh_token,created_at,expired_at) VALUES ($1,$2,$3,$4)"
	_, err := tx.Exec(ctx, query, refreshtoken.User_id, refreshtoken.Hashed_refresh_token, refreshtoken.Created_at, refreshtoken.Expired_at)
	if err != nil {
		repository.Log.Panic("failed to query into database", zap.Error(err))
	}
}

func (repository *AdminRepository) UpdateRefreshTokenWithTx(ctx context.Context, tx pgx.Tx, tokenStatus string, userUUID string) {
	query := "UPDATE admin_refresh_tokens SET status = $1 WHERE user_id = $2 AND created_at = (SELECT MAX(created_at) FROM refresh_tokens WHERE user_id = $2)"
	_, err := tx.Exec(ctx, query, tokenStatus, userUUID)
	if err != nil {
		repository.Log.Panic("failed to query into database", zap.Error(err))
	}
}

func (repository *AdminRepository) FindLatestRefreshToken(ctx context.Context, tx pgx.Tx) (string, error) {
	query := "SELECT hashed_refresh_token FROM admin_refresh_tokens ORDER BY created_at DESC LIMIT 1"

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

func (repository *AdminRepository) CheckAdminExistence(ctx context.Context, userUUID string) error {
	query := "SELECT username FROM admins WHERE id=$1 AND role='admin' AND is_active=true"

	var username string
	err := repository.DB.QueryRow(ctx, query, userUUID).Scan(&username)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errors.New("admin already exist")
		}
		repository.Log.Panic("failed to query database", zap.Error(err))
	}

	return nil
}

func (repository *AdminRepository) CheckBothAdminExistence(ctx context.Context, tx pgx.Tx, userUUID string) error {
	query := "SELECT username FROM admins WHERE id=$1 AND (role='admin' OR role='superadmin') AND is_active=true"

	var username string
	err := tx.QueryRow(ctx, query, userUUID).Scan(&username)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errors.New("admin already exist")
		}
		repository.Log.Panic("failed to query database", zap.Error(err))
	}

	return nil
}

func (repository *AdminRepository) CheckSuperAdminExistence(ctx context.Context, userUUID string) error {
	query := "SELECT username FROM admins WHERE id=$1 AND role='superadmin' AND is_active=true"

	var username string
	err := repository.DB.QueryRow(ctx, query, userUUID).Scan(&username)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errors.New("admin already exist")
		}
		repository.Log.Panic("failed to query database", zap.Error(err))
	}

	return nil
}
