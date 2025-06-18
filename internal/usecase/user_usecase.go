package usecase

import (
	"brightmart-backend/internal/helper"
	"brightmart-backend/internal/model"
	"brightmart-backend/internal/repository"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/knadh/koanf/v2"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"io"
	"time"
)

type UserUsecase struct {
	NotificationUsecase *NotificationUsecase
	UserRepository      *repository.UserRepository
	DB                  *pgxpool.Pool
	OAuth2              *oauth2.Config
	Log                 *zap.Logger
	Config              *koanf.Koanf
}

func NewUserUsecase(notificationUsecase *NotificationUsecase, userRepository *repository.UserRepository, db *pgxpool.Pool, oauth2 *oauth2.Config, zap *zap.Logger, koanf *koanf.Koanf) *UserUsecase {
	return &UserUsecase{
		NotificationUsecase: notificationUsecase,
		UserRepository:      userRepository,
		DB:                  db,
		OAuth2:              oauth2,
		Log:                 zap,
		Config:              koanf,
	}
}

func (usecase *UserUsecase) Register(ctx context.Context, payload model.UserCreateRequest, errorMap map[string]string) map[string]string {
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

	user := model.User{
		Id:         uuid.New().String(),
		Username:   payload.Username,
		Email:      payload.Email,
		Password:   string(hashedPassword),
		Created_at: now,
		Updated_at: now,
	}

	err = usecase.UserRepository.CheckUsernameUnique(ctx, tx, user.Username)
	if err != nil {
		errorMap["username"] = err.Error()
		return errorMap
	}

	err = usecase.UserRepository.CheckEmailUnique(ctx, tx, user.Email)
	if err != nil {
		errorMap["email"] = err.Error()
		return errorMap
	}

	usecase.UserRepository.Register(ctx, tx, user)

	code, err := helper.GenerateVerificationCode(6)
	if err != nil {
		respErr = errors.New("failed to generate verification code")
		usecase.Log.Panic(respErr.Error(), zap.Error(err))
	}

	err = usecase.NotificationUsecase.SendRegisterNotification(ctx, tx, payload.Username, payload.Email, code)
	if err != nil {
		errorMap["internal"] = err.Error()
		return errorMap
	}

	hashedCode := helper.GenerateSHA256Hash(code)
	usecase.UserRepository.SaveUserInCache(ctx, user.Email, hashedCode)

	return nil
}

func (usecase *UserUsecase) VerifyUser(ctx context.Context, payload model.UserVerificationRequest, errorMap map[string]string) (model.TokenResponse, map[string]string) {
	var respErr error

	if payload.Email == "" {
		errorMap["email"] = "email is required to not be empty"
		return model.TokenResponse{}, errorMap
	} else if len(payload.Email) < 16 {
		errorMap["email"] = "email must be at least 16 characters"
		return model.TokenResponse{}, errorMap
	} else if len(payload.Email) > 80 {
		errorMap["email"] = "email must be at most 80 characters"
		return model.TokenResponse{}, errorMap
	}

	if payload.Code == "" {
		errorMap["code"] = "code is required to not be empty"
		return model.TokenResponse{}, errorMap
	} else if len(payload.Code) != 6 {
		errorMap["code"] = "code must be least 6 characters"
		return model.TokenResponse{}, errorMap
	}

	// start transaction
	tx, err := usecase.DB.Begin(ctx)
	if err != nil {
		respErr = errors.New("failed to start transaction")
		usecase.Log.Panic(respErr.Error(), zap.Error(err))
	}

	defer helper.CommitOrRollback(ctx, tx, usecase.Log)

	id, err := usecase.UserRepository.FindNotVerifiedUserIdByEmail(ctx, tx, payload.Email)
	if err != nil {
		errorMap["user"] = err.Error()
		return model.TokenResponse{}, errorMap
	}

	code, err := usecase.UserRepository.FindUserCodeByEmailInCache(ctx, payload.Email)
	if err != nil {
		errorMap["code"] = err.Error()
		return model.TokenResponse{}, errorMap
	}

	requestHashedCode := helper.GenerateSHA256Hash(payload.Code)
	if requestHashedCode != code {
		errorMap["code"] = "invalid verification code"
		return model.TokenResponse{}, errorMap
	}

	usecase.UserRepository.UpdateUserStatus(ctx, tx, payload.Email, true, time.Now())
	usecase.UserRepository.DeleteUserCodeInCache(ctx, payload.Email)

	tokenResponse := usecase.generateTokens(ctx, tx, id)

	return tokenResponse, nil
}

func (usecase *UserUsecase) ResendCode(ctx context.Context, payload model.UserResendCodeRequest, errorMap map[string]string) map[string]string {
	var respErr error

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

	// start transaction
	tx, err := usecase.DB.Begin(ctx)
	if err != nil {
		respErr = errors.New("failed to start transaction")
		usecase.Log.Panic(respErr.Error(), zap.Error(err))
	}

	defer helper.CommitOrRollback(ctx, tx, usecase.Log)

	username, err := usecase.UserRepository.FindUsenamedByEmail(ctx, tx, payload.Email)
	if err != nil {
		errorMap["user"] = err.Error()
		return errorMap
	}

	usecase.UserRepository.DeleteUserCodeInCache(ctx, payload.Email)

	code, err := helper.GenerateVerificationCode(6)
	if err != nil {
		respErr = errors.New("failed to generate verification code")
		usecase.Log.Panic(respErr.Error(), zap.Error(err))
	}

	err = usecase.NotificationUsecase.SendRegisterNotification(ctx, tx, username, payload.Email, code)
	if err != nil {
		errorMap["internal"] = err.Error()
		return errorMap
	}

	hashedCode := helper.GenerateSHA256Hash(code)
	usecase.UserRepository.SaveUserInCache(ctx, payload.Email, hashedCode)

	return nil
}

func (usecase *UserUsecase) Login(ctx context.Context, payload model.UserLoginRequest, errorMap map[string]string) (model.TokenResponse, map[string]string) {
	var respErr error

	if payload.Email == "" {
		errorMap["email"] = "email is required to not be empty"
		return model.TokenResponse{}, errorMap
	} else if len(payload.Email) < 16 {
		errorMap["email"] = "email must be at least 16 characters"
		return model.TokenResponse{}, errorMap
	} else if len(payload.Email) > 80 {
		errorMap["email"] = "email must be at most 80 characters"
		return model.TokenResponse{}, errorMap
	}

	if payload.Password == "" {
		errorMap["password"] = "password is required to not be empty"
		return model.TokenResponse{}, errorMap
	} else if len(payload.Password) < 5 {
		errorMap["password"] = "password must be at least 5 characters"
		return model.TokenResponse{}, errorMap
	} else if len(payload.Password) > 20 {
		errorMap["password"] = "password must be at most 20 characters"
		return model.TokenResponse{}, errorMap
	}

	// start transaction
	tx, err := usecase.DB.Begin(ctx)
	if err != nil {
		respErr = errors.New("failed to start transaction")
		usecase.Log.Panic(respErr.Error(), zap.Error(err))
	}

	defer helper.CommitOrRollback(ctx, tx, usecase.Log)

	user, err := usecase.UserRepository.Login(ctx, tx, payload.Email)
	if err != nil {
		errorMap["user"] = err.Error()
		return model.TokenResponse{}, errorMap
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(payload.Password))
	if err != nil {
		errorMap["password"] = "wrong email or password"
		return model.TokenResponse{}, errorMap
	}

	tokenResponse := usecase.generateTokens(ctx, tx, user.Id)

	return tokenResponse, nil
}

func (usecase *UserUsecase) OAuthCallback(ctx context.Context, code string, state string, errorMap map[string]string) (model.TokenResponse, map[string]string) {
	tx, err := usecase.DB.Begin(ctx)
	if err != nil {
		usecase.Log.Panic("failed to start transaction", zap.Error(err))
	}
	defer helper.CommitOrRollback(ctx, tx, usecase.Log)

	err = usecase.UserRepository.CheckUserStateExistenceInCache(ctx, state)
	if err != nil {
		errorMap["state"] = err.Error()
		return model.TokenResponse{}, errorMap
	}

	usecase.UserRepository.DeleteUserStateInCache(ctx, state)

	token, err := usecase.OAuth2.Exchange(ctx, code)
	if err != nil {
		errorMap["code"] = "code not found"
		return model.TokenResponse{}, errorMap
	}

	client := usecase.OAuth2.Client(ctx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		errorMap["third-party"] = "third party (google) is down or no connection"
		return model.TokenResponse{}, errorMap
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		usecase.Log.Panic("failed to read response body", zap.Error(err))
	}

	var googleUser model.GoogleUserInfoResponse
	err = json.Unmarshal(body, &googleUser)
	if err != nil {
		usecase.Log.Panic("failed to unmarshal json response", zap.Error(err))
	}

	// Step 1: Find user by provider_user_id (Google sub)
	var id string
	_, err = usecase.UserRepository.FindByProviderUserID(ctx, tx, googleUser.ID)
	if err != nil {
		// User found via register then oauth → generate tokens
		id, err = usecase.UserRepository.FindUserIdByEmail(ctx, tx, googleUser.Email)
		if err == nil {
			usecase.UserRepository.UpdateProviderUserID(ctx, tx, googleUser.ID, googleUser.Email, time.Now())
			tokenResponse := usecase.generateTokens(ctx, tx, id)
			return tokenResponse, nil
		}
	}

	// Step 3: New user registration
	var username string

	//fmt.Println("got here -1", googleUser.Name, username)
	checkErr := usecase.UserRepository.CheckUsernameUnique(ctx, tx, googleUser.Name)
	if checkErr == nil || len(googleUser.Name) < 5 {
		//fmt.Println("got here", googleUser.Name, username)
		username, err = helper.GenerateUsername(googleUser.Name)
		if err != nil {
			usecase.Log.Panic("failed to generate username", zap.Error(err))
		}
		//fmt.Println("got here2", googleUser.Name, username)
	}

	password, err := helper.GenerateRandomPasswordChar20()
	if err != nil {
		usecase.Log.Panic("failed to generate random password 20 char", zap.Error(err))
	}

	fmt.Println("password", password)

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		usecase.Log.Panic("failed to hash password with bcrypt", zap.Error(err))
	}

	newUser := model.User{
		Id:               uuid.New().String(),
		Username:         username,
		Email:            googleUser.Email,
		Profile_picture:  &googleUser.Picture,
		Auth_provider:    "google",
		Provider_user_id: &googleUser.ID,
		Is_verified:      true,
		Password:         string(hashedPassword),
		Created_at:       time.Now(),
		Updated_at:       time.Now(),
	}

	usecase.UserRepository.RegisterViaOAuth(ctx, tx, newUser)

	tokenResponse := usecase.generateTokens(ctx, tx, newUser.Id)

	return tokenResponse, nil
}

func (usecase *UserUsecase) generateTokens(ctx context.Context, tx pgx.Tx, userId string) model.TokenResponse {
	secretKeyAccess := usecase.Config.String("SECRET_KEY_ACCESS_TOKEN")
	secretKeyAccessByte := []byte(secretKeyAccess)

	now := time.Now()

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":  userId,
		"exp": now.Add(5 * time.Minute).Unix(),
	})

	accessTokenString, err := accessToken.SignedString(secretKeyAccessByte)
	if err != nil {
		usecase.Log.Panic("failed to sign access token", zap.Error(err))
	}

	secretKeyRefresh := usecase.Config.String("SECRET_KEY_REFRESH_TOKEN")
	secretKeyRefreshByte := []byte(secretKeyRefresh)

	addedTime := now.Add(30 * 24 * time.Hour)
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":  userId,
		"exp": addedTime.Unix(),
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
		Expired_at:           addedTime,
	}

	usecase.UserRepository.UpdateRefreshTokenWithTx(ctx, tx, "Revoke", userId)
	usecase.UserRepository.AddRefreshTokenWithTx(ctx, tx, refreshTokenToDB)

	tokenResponse := model.TokenResponse{
		Access_token:             accessTokenString,
		Access_token_expires_in:  int((5 * time.Minute).Seconds()),
		Refresh_token:            refreshTokenString,
		Refresh_token_expires_in: int((30 * 24 * time.Hour).Seconds()),
		Token_type:               "bearer",
	}

	return tokenResponse
}

func (usecase *UserUsecase) OAuth(ctx context.Context) string {
	var respErr error

	state, err := helper.GenerateState()
	if err != nil {
		respErr = errors.New("failed to sign a token")
		usecase.Log.Panic(respErr.Error(), zap.Error(err))
	}

	usecase.UserRepository.SaveUserStateInCache(ctx, state)

	url := usecase.OAuth2.AuthCodeURL(state, oauth2.AccessTypeOffline)
	return url
}

func (usecase *UserUsecase) CheckUserExistance(ctx context.Context, userUUID string) error {
	err := usecase.UserRepository.CheckUserExistence(ctx, userUUID)
	if err != nil {
		usecase.Log.Debug(err.Error())
		return err
	}

	return nil
}
