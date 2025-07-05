package usecase

import (
	"brightmart-backend/internal/helper"
	"brightmart-backend/internal/model"
	"brightmart-backend/internal/repository"
	"context"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/knadh/koanf/v2"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"time"
)

type AdminUsecase struct {
	AdminRepository *repository.AdminRepository
	DB              *pgxpool.Pool
	OAuth2          *oauth2.Config
	Log             *zap.Logger
	Config          *koanf.Koanf
}

func NewAdminUsecase(adminRepository *repository.AdminRepository, db *pgxpool.Pool, oauth2 *oauth2.Config, zap *zap.Logger, koanf *koanf.Koanf) *AdminUsecase {
	return &AdminUsecase{
		AdminRepository: adminRepository,
		DB:              db,
		OAuth2:          oauth2,
		Log:             zap,
		Config:          koanf,
	}
}

func (usecase *AdminUsecase) Login(ctx context.Context, payload model.UserLoginRequest, errorMap map[string]string) (model.Token, map[string]string) {
	var respErr error
	token := model.Token{}

	if payload.Email == "" {
		errorMap["email"] = "email is required to not be empty"
		return token, errorMap
	} else if len(payload.Email) < 16 {
		errorMap["email"] = "email must be at least 16 characters"
		return token, errorMap
	} else if len(payload.Email) > 80 {
		errorMap["email"] = "email must be at most 80 characters"
		return token, errorMap
	}

	if payload.Password == "" {
		errorMap["password"] = "password is required to not be empty"
		return token, errorMap
	} else if len(payload.Password) < 5 {
		errorMap["password"] = "password must be at least 5 characters"
		return token, errorMap
	} else if len(payload.Password) > 20 {
		errorMap["password"] = "password must be at most 20 characters"
		return token, errorMap
	}

	// start transaction
	tx, err := usecase.DB.Begin(ctx)
	if err != nil {
		respErr = errors.New("failed to start transaction")
		usecase.Log.Panic(respErr.Error(), zap.Error(err))
	}

	defer helper.CommitOrRollback(ctx, tx, usecase.Log)

	admin, err := usecase.AdminRepository.Login(ctx, tx, payload.Email)
	if err != nil {
		errorMap["email"] = err.Error()
		return token, errorMap
	}

	err = bcrypt.CompareHashAndPassword([]byte(admin.Password), []byte(payload.Password))
	if err != nil {
		errorMap["password"] = "wrong email or password"
		return token, errorMap
	}

	tokenResponse := usecase.generateTokens(ctx, tx, admin.Id)

	return tokenResponse, nil
}

func (usecase *AdminUsecase) generateTokens(ctx context.Context, tx pgx.Tx, userId string) model.Token {
	secretKeyAccess := usecase.Config.String("ADMIN_SECRET_KEY_ACCESS_TOKEN")
	secretKeyAccessByte := []byte(secretKeyAccess)

	now := time.Now()
	accessExpirationTime := now.Add(5 * time.Minute)

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":  userId,
		"exp": accessExpirationTime.Unix(),
	})

	accessTokenString, err := accessToken.SignedString(secretKeyAccessByte)
	if err != nil {
		usecase.Log.Panic("failed to sign access token", zap.Error(err))
	}

	secretKeyRefresh := usecase.Config.String("ADMIN_SECRET_KEY_REFRESH_TOKEN")
	secretKeyRefreshByte := []byte(secretKeyRefresh)

	refreshExpirationTime := now.Add(30 * 24 * time.Hour)
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":  userId,
		"exp": refreshExpirationTime.Unix(),
	})

	refreshTokenString, err := refreshToken.SignedString(secretKeyRefreshByte)
	if err != nil {
		usecase.Log.Panic("failed to sign refresh token", zap.Error(err))
	}

	hashedRefreshToken := helper.GenerateSHA256Hash(refreshTokenString)

	refreshTokenToDB := model.RefreshToken{
		User_id:              userId,
		Hashed_refresh_token: hashedRefreshToken,
		Created_at:           now,
		Expired_at:           refreshExpirationTime,
	}

	usecase.AdminRepository.UpdateRefreshTokenWithTx(ctx, tx, "Revoke", userId)
	usecase.AdminRepository.AddRefreshTokenWithTx(ctx, tx, refreshTokenToDB)

	tokenResponse := model.Token{
		Access_token:             accessTokenString,
		Refresh_token:            refreshTokenString,
		Access_token_expires_in:  accessExpirationTime,
		Refresh_token_expires_in: refreshExpirationTime,
	}

	return tokenResponse
}

func (usecase *AdminUsecase) CheckAdminExistance(ctx context.Context, userUUID string) error {
	err := usecase.AdminRepository.CheckAdminExistence(ctx, userUUID)
	if err != nil {
		usecase.Log.Debug(err.Error())
		return err
	}

	return nil
}

func (usecase *AdminUsecase) CheckSuperAdminExistance(ctx context.Context, userUUID string) error {
	err := usecase.AdminRepository.CheckSuperAdminExistence(ctx, userUUID)
	if err != nil {
		usecase.Log.Debug(err.Error())
		return err
	}

	return nil
}
