package usecase

import (
	"brightmart-backend/internal/helper"
	"brightmart-backend/internal/model"
	"brightmart-backend/internal/repository"
	"context"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/knadh/koanf/v2"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"net/http"
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

func (usecase *AdminUsecase) generateTokenResponse(ctx context.Context, tx pgx.Tx, userId string) model.TokenResponse {
	secretKeyAccess := usecase.Config.String("ADMIN_SECRET_KEY_ACCESS_TOKEN")
	secretKeyAccessByte := []byte(secretKeyAccess)

	now := time.Now()
	accessTokenDuration := now.Add(5 * time.Minute)

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":  userId,
		"exp": accessTokenDuration.Unix(),
	})

	accessTokenString, err := accessToken.SignedString(secretKeyAccessByte)
	if err != nil {
		usecase.Log.Panic("failed to sign access token", zap.Error(err))
	}

	secretKeyRefresh := usecase.Config.String("ADMIN_SECRET_KEY_REFRESH_TOKEN")
	secretKeyRefreshByte := []byte(secretKeyRefresh)

	refreshTokenDuration := now.Add(30 * 24 * time.Hour)
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":  userId,
		"exp": refreshTokenDuration.Unix(),
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
		Expired_at:           refreshTokenDuration,
	}

	usecase.AdminRepository.UpdateRefreshTokenWithTx(ctx, tx, "Revoke", userId)
	usecase.AdminRepository.AddRefreshTokenWithTx(ctx, tx, refreshTokenToDB)

	tokenResponse := model.TokenResponse{
		Access_token:             accessTokenString,
		Access_token_expires_in:  accessTokenDuration.Second(),
		Refresh_token:            refreshTokenString,
		Refresh_token_expires_in: refreshTokenDuration.Second(),
		Token_type:               "bearer",
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

func (usecase *AdminUsecase) RefreshTokenRenewal(ctx context.Context, payload model.RenewalTokenRequest, errorMap map[string]string) (model.Token, map[string]string) {
	var err error
	var respErr error
	tokenResponse := model.Token{}

	if payload.Refresh_token == "" {
		errorMap["refresh_token"] = "refresh_token is required to not be empty"
		return tokenResponse, errorMap
	} else if len(payload.Refresh_token) != 164 {
		errorMap["refresh_token"] = "refresh_token must be 164 characters"
		return tokenResponse, errorMap
	}

	tx, err := usecase.DB.Begin(ctx)
	if err != nil {
		usecase.Log.Panic("failed to start transaction", zap.Error(err))
	}

	defer helper.CommitOrRollback(ctx, tx, usecase.Log)

	secretKeyRefresh := usecase.Config.String("ADMIN_SECRET_KEY_REFRESH_TOKEN")
	secretKeyRefreshByte := []byte(secretKeyRefresh)

	token, err := jwt.Parse(payload.Refresh_token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, http.ErrNotSupported
		}
		return secretKeyRefreshByte, nil
	})

	if err != nil {
		if err == jwt.ErrTokenMalformed {
			err = errors.New("token is malformed")
			usecase.Log.Debug(err.Error())
			errorMap["refresh_token"] = err.Error()
			return tokenResponse, errorMap
		} else if err.Error() == "token has invalid claims: token is expired" {
			err = errors.New("token is expired")
			usecase.Log.Debug(err.Error())
			errorMap["refresh_token"] = err.Error()
			return tokenResponse, errorMap
		} else {
			err = errors.New("token is invalid")
			usecase.Log.Debug(err.Error())
			errorMap["refresh_token"] = err.Error()
			return tokenResponse, errorMap
		}
	}

	var userID string
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if val, exists := claims["id"]; exists {
			if strVal, ok := val.(string); ok {
				userID = strVal
			}
		} else {
			err = errors.New("token is invalid")
			usecase.Log.Debug(err.Error())
			errorMap["refresh_token"] = err.Error()
			return tokenResponse, errorMap
		}
	}

	err = usecase.AdminRepository.CheckBothAdminExistence(ctx, tx, userID)
	if err != nil {
		usecase.Log.Warn(err.Error())
		errorMap["user"] = err.Error()
		return tokenResponse, errorMap
	}

	hashedRequestRefreshTokenHex := helper.GenerateSHA256Hash(payload.Refresh_token)

	hashedDBRefreshTokenHex, err := usecase.AdminRepository.FindLatestRefreshToken(ctx, tx)
	if err != nil {
		usecase.Log.Warn(err.Error())
		errorMap["refresh_token"] = err.Error()
		return tokenResponse, errorMap
	}

	if hashedRequestRefreshTokenHex != hashedDBRefreshTokenHex {
		usecase.AdminRepository.UpdateRefreshTokenWithTx(ctx, tx, "Revoke", userID)
		respErr = errors.New("refresh token reuse detected. for security reasons, you have been logged out. please sign in again.")
		usecase.Log.Warn(respErr.Error())
		errorMap["refresh_token"] = respErr.Error()
		return tokenResponse, errorMap
	}

	tokenResponse = usecase.generateTokens(ctx, tx, userID)

	return tokenResponse, nil
}

func (usecase *AdminUsecase) AccessTokenRenewal(ctx context.Context, payload model.RenewalTokenRequest, errorMap map[string]string) (model.Token, map[string]string) {
	var err error
	var respErr error
	tokenResponse := model.Token{}

	if payload.Refresh_token == "" {
		errorMap["refresh_token"] = "refresh_token is required to not be empty"
		return tokenResponse, errorMap
	} else if len(payload.Refresh_token) != 164 {
		errorMap["refresh_token"] = "refresh_token must be 164 characters"
		return tokenResponse, errorMap
	}

	tx, err := usecase.DB.Begin(ctx)
	if err != nil {
		usecase.Log.Panic("failed to start transaction", zap.Error(err))
	}

	defer helper.CommitOrRollback(ctx, tx, usecase.Log)

	secretKeyRefresh := usecase.Config.String("SECRET_KEY_REFRESH_TOKEN")
	secretKeyRefreshByte := []byte(secretKeyRefresh)

	token, err := jwt.Parse(payload.Refresh_token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, http.ErrNotSupported
		}
		return secretKeyRefreshByte, nil
	})

	if err != nil {
		if err == jwt.ErrTokenMalformed {
			err = errors.New("token is malformed")
			usecase.Log.Debug(err.Error())
			errorMap["refresh_token"] = err.Error()
			return tokenResponse, errorMap
		} else if err.Error() == "token has invalid claims: token is expired" {
			err = errors.New("token is expired")
			usecase.Log.Debug(err.Error())
			errorMap["refresh_token"] = err.Error()
			return tokenResponse, errorMap
		} else {
			err = errors.New("token is invalid")
			usecase.Log.Debug(err.Error())
			errorMap["refresh_token"] = err.Error()
			return tokenResponse, errorMap
		}
	}

	var userID string
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if val, exists := claims["id"]; exists {
			if strVal, ok := val.(string); ok {
				userID = strVal
			}
		} else {
			err = errors.New("token is invalid")
			usecase.Log.Debug(err.Error())
			errorMap["refresh_token"] = err.Error()
			return tokenResponse, errorMap
		}
	}

	err = usecase.AdminRepository.CheckBothAdminExistence(ctx, tx, userID)
	if err != nil {
		usecase.Log.Warn(err.Error())
		errorMap["user"] = err.Error()
		return tokenResponse, errorMap
	}

	hashedRequestRefreshTokenHex := helper.GenerateSHA256Hash(payload.Refresh_token)

	hashedDBRefreshTokenHex, err := usecase.AdminRepository.FindLatestRefreshToken(ctx, tx)
	if err != nil {
		usecase.Log.Warn(err.Error())
		errorMap["refresh_token"] = err.Error()
		return tokenResponse, errorMap
	}

	if hashedRequestRefreshTokenHex != hashedDBRefreshTokenHex {
		usecase.AdminRepository.UpdateRefreshTokenWithTx(ctx, tx, "Revoke", userID)
		respErr = errors.New("refresh token reuse detected. for security reasons, you have been logged out. please sign in again.")
		usecase.Log.Warn(respErr.Error())
		errorMap["refresh_token"] = respErr.Error()
		return tokenResponse, errorMap
	}

	secretKeyAccess := usecase.Config.String("SECRET_KEY_ACCESS_TOKEN")
	secretKeyAccessByte := []byte(secretKeyAccess)

	now := time.Now()
	accessExpirationTime := now.Add(5 * time.Minute)

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":  userID,
		"exp": accessExpirationTime.Unix(),
	})

	accessTokenString, err := accessToken.SignedString(secretKeyAccessByte)
	if err != nil {
		usecase.Log.Panic("failed to sign access token", zap.Error(err))
	}

	accessTokenResponse := model.Token{
		Access_token:            accessTokenString,
		Access_token_expires_in: accessExpirationTime,
	}

	return accessTokenResponse, nil
}

func (usecase *AdminUsecase) CreateAdmin(ctx context.Context, superadminID string, payload model.AdminCreateRequest, errorMap map[string]string) map[string]string {
	var respErr error

	if payload.Username == "" {
		errorMap["username"] = "username is required to not be empty"
		return errorMap
	} else if len(payload.Username) < 4 {
		errorMap["username"] = "username must be at least 4 characters"
		return errorMap
	} else if len(payload.Username) > 22 {
		errorMap["username"] = "username must be at most 22 characters"
		return errorMap
	}

	if payload.Email == "" {
		errorMap["email"] = "email is required to not be empty"
		return errorMap
	} else if len(payload.Email) < 16 {
		errorMap["email"] = "email must be at least 16 characters"
		return errorMap
	} else if len(payload.Email) > 80 {
		errorMap["email"] = "email must be at most 80 characters"
		return errorMap
	}

	if payload.Password == "" {
		errorMap["password"] = "password is required to not be empty"
		return errorMap
	} else if len(payload.Password) < 5 {
		errorMap["password"] = "password must be at least 5 characters"
		return errorMap
	} else if len(payload.Password) > 20 {
		errorMap["password"] = "password must be at most 20 characters"
		return errorMap
	}

	// start transaction
	tx, err := usecase.DB.Begin(ctx)
	if err != nil {
		respErr = errors.New("failed to start transaction")
		usecase.Log.Panic(respErr.Error(), zap.Error(err))
	}

	defer helper.CommitOrRollback(ctx, tx, usecase.Log)

	now := time.Now()
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)
	if err != nil {
		respErr = errors.New("error generating password hash")
		usecase.Log.Panic(respErr.Error(), zap.Error(err))
	}

	err = usecase.AdminRepository.CheckUsernameUnique(ctx, tx, payload.Username)
	if err != nil {
		errorMap["username"] = err.Error()
		return errorMap
	}

	err = usecase.AdminRepository.CheckEmailUnique(ctx, tx, payload.Email)
	if err != nil {
		errorMap["email"] = err.Error()
		return errorMap
	}

	admin := model.Admin{
		Id:        uuid.New().String(),
		Username:  payload.Username,
		Email:     payload.Email,
		Password:  string(hashedPassword),
		CreatedBy: superadminID,
		Role:      "admin",
		IsActive:  true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	usecase.AdminRepository.CreateAdmin(ctx, tx, admin)
	return nil
}
