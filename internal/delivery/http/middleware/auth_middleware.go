package middleware

import (
	"brightmart-backend/internal/helper"
	"brightmart-backend/internal/usecase"
	"context"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/julienschmidt/httprouter"
	"github.com/knadh/koanf/v2"
	"go.uber.org/zap"
	"net/http"
	"strings"
)

type AuthMiddleware struct {
	Handler      http.Handler
	Log          *zap.Logger
	Config       *koanf.Koanf
	UserUsecase  *usecase.UserUsecase
	AdminUsecase *usecase.AdminUsecase
}

func NewAuthMiddleware(handler http.Handler, zap *zap.Logger, koanf *koanf.Koanf, userUsecase *usecase.UserUsecase, adminUsecase *usecase.AdminUsecase) *AuthMiddleware {
	return &AuthMiddleware{
		Handler:      handler,
		Log:          zap,
		Config:       koanf,
		UserUsecase:  userUsecase,
		AdminUsecase: adminUsecase,
	}
}

func (middleware *AuthMiddleware) MobileProtectedMiddleware(next httprouter.Handle) httprouter.Handle {
	return func(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {
		var err error
		errorMap := map[string]string{}

		ctx := request.Context()

		headerToken := request.Header.Get("Authorization")

		if headerToken == "" {
			err = errors.New("no token provided")
			middleware.Log.Debug(err.Error())
			errorMap["auth"] = err.Error()
			helper.WriteErrorResponse(writer, http.StatusUnauthorized, errorMap)
			return
		}

		splitToken := strings.Split(headerToken, "Bearer ")
		if len(splitToken) != 2 {
			err = errors.New("token format is not match")
			middleware.Log.Debug(err.Error())
			errorMap["auth"] = err.Error()
			helper.WriteErrorResponse(writer, http.StatusUnauthorized, errorMap)
			return
		}

		secretKey := middleware.Config.String("USER_SECRET_KEY_ACCESS_TOKEN")
		secretKeyByte := []byte(secretKey)

		token, err := jwt.Parse(splitToken[1], func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, http.ErrNotSupported
			}
			return secretKeyByte, nil
		})

		if err != nil {
			if err == jwt.ErrTokenMalformed {
				err = errors.New("token is malformed")
				middleware.Log.Debug(err.Error())
				errorMap["auth"] = err.Error()
				helper.WriteErrorResponse(writer, http.StatusUnauthorized, errorMap)
				return
			} else if err.Error() == "token has invalid claims: token is expired" {
				err = errors.New("token is expired")
				middleware.Log.Debug(err.Error())
				errorMap["auth"] = err.Error()
				helper.WriteErrorResponse(writer, http.StatusUnauthorized, errorMap)
				return
			} else {
				err = errors.New("token is invalid")
				middleware.Log.Debug(err.Error())
				errorMap["auth"] = err.Error()
				helper.WriteErrorResponse(writer, http.StatusUnauthorized, errorMap)
				return
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
				middleware.Log.Debug(err.Error())
				errorMap["auth"] = err.Error()
				helper.WriteErrorResponse(writer, http.StatusUnauthorized, errorMap)
				return
			}
		}

		err = middleware.UserUsecase.CheckUserExistance(request.Context(), userID)
		if err != nil {
			err = errors.New("user not found, please register")
			middleware.Log.Debug(err.Error())
			errorMap["auth"] = err.Error()
			helper.WriteErrorResponse(writer, http.StatusUnauthorized, errorMap)
			return
		}

		middleware.Log.Debug("User:" + userID)

		ctx = context.WithValue(ctx, "user_uuid", userID)
		request = request.WithContext(ctx)

		next(writer, request.WithContext(ctx), params)
	}
}

func (middleware *AuthMiddleware) WebAdminProtectedMiddleware(next httprouter.Handle) httprouter.Handle {
	return func(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {
		var err error
		errorMap := map[string]string{}

		ctx := request.Context()
		cookie, err := request.Cookie("access_token")
		if err != nil {
			if err == http.ErrNoCookie {
				errorMap["auth"] = "no token provided"
				helper.WriteErrorResponse(writer, http.StatusUnauthorized, errorMap)
			} else {
				errorMap["auth"] = err.Error()
				helper.WriteErrorResponse(writer, http.StatusUnauthorized, errorMap)
			}
		}

		headerToken := cookie.Value
		secretKey := middleware.Config.String("ADMIN_SECRET_KEY_ACCESS_TOKEN")
		secretKeyByte := []byte(secretKey)

		token, err := jwt.Parse(headerToken, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, http.ErrNotSupported
			}
			return secretKeyByte, nil
		})

		if err != nil {
			if err == jwt.ErrTokenMalformed {
				errorMap["auth"] = "token is malformed"
				helper.WriteErrorResponse(writer, http.StatusUnauthorized, errorMap)
			} else if err.Error() == "token has invalid claims: token is expired" {
				errorMap["auth"] = "token is expired"
				helper.WriteErrorResponse(writer, http.StatusUnauthorized, errorMap)
			} else {
				errorMap["auth"] = "token is invalid"
				helper.WriteErrorResponse(writer, http.StatusUnauthorized, errorMap)
			}
		}

		var userID string
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			if val, exists := claims["id"]; exists {
				if strVal, ok := val.(string); ok {
					userID = strVal
				}
			} else {
				errorMap["auth"] = "token is invalid"
				helper.WriteErrorResponse(writer, http.StatusUnauthorized, errorMap)
			}
		}

		err = middleware.AdminUsecase.CheckAdminExistance(ctx, userID)
		if err != nil {
			err = errors.New("admin not found, please register")
			middleware.Log.Debug(err.Error())
			errorMap["auth"] = err.Error()
			helper.WriteErrorResponse(writer, http.StatusUnauthorized, errorMap)
			return
		}

		middleware.Log.Debug("Admin:" + userID)

		ctx = context.WithValue(ctx, "admin_uuid", userID)
		request = request.WithContext(ctx)

		next(writer, request.WithContext(ctx), params)
	}
}

func (middleware *AuthMiddleware) WebSuperAdminProtectedMiddleware(next httprouter.Handle) httprouter.Handle {
	return func(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {
		var err error
		errorMap := map[string]string{}

		ctx := request.Context()
		cookie, err := request.Cookie("access_token")
		if err != nil {
			if err == http.ErrNoCookie {
				errorMap["auth"] = "no token provided"
				helper.WriteErrorResponse(writer, http.StatusUnauthorized, errorMap)
			} else {
				errorMap["auth"] = err.Error()
				helper.WriteErrorResponse(writer, http.StatusUnauthorized, errorMap)
			}
		}

		headerToken := cookie.Value
		secretKey := middleware.Config.String("ADMIN_SECRET_KEY_ACCESS_TOKEN")
		secretKeyByte := []byte(secretKey)

		token, err := jwt.Parse(headerToken, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, http.ErrNotSupported
			}
			return secretKeyByte, nil
		})

		if err != nil {
			if err == jwt.ErrTokenMalformed {
				errorMap["auth"] = "token is malformed"
				helper.WriteErrorResponse(writer, http.StatusUnauthorized, errorMap)
			} else if err.Error() == "token has invalid claims: token is expired" {
				errorMap["auth"] = "token is expired"
				helper.WriteErrorResponse(writer, http.StatusUnauthorized, errorMap)
			} else {
				errorMap["auth"] = "token is invalid"
				helper.WriteErrorResponse(writer, http.StatusUnauthorized, errorMap)
			}
		}

		var userID string
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			if val, exists := claims["id"]; exists {
				if strVal, ok := val.(string); ok {
					userID = strVal
				}
			} else {
				errorMap["auth"] = "token is invalid"
				helper.WriteErrorResponse(writer, http.StatusUnauthorized, errorMap)
			}
		}

		err = middleware.AdminUsecase.CheckSuperAdminExistance(ctx, userID)
		if err != nil {
			err = errors.New("admin not found, please register")
			middleware.Log.Debug(err.Error())
			errorMap["auth"] = err.Error()
			helper.WriteErrorResponse(writer, http.StatusUnauthorized, errorMap)
			return
		}

		middleware.Log.Debug("Superadmin:" + userID)

		ctx = context.WithValue(ctx, "superadmin_uuid", userID)
		request = request.WithContext(ctx)

		next(writer, request.WithContext(ctx), params)
	}
}

func (middleware *AuthMiddleware) WebProtectedMiddleware(next httprouter.Handle) httprouter.Handle {
	return func(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {
		var err error
		errorMap := map[string]string{}

		ctx := request.Context()

		headerToken := request.Header.Get("Authorization")

		if headerToken == "" {
			err = errors.New("no token provided")
			middleware.Log.Debug(err.Error())
			errorMap["auth"] = err.Error()
			helper.WriteErrorResponse(writer, http.StatusUnauthorized, errorMap)
			return
		}

		splitToken := strings.Split(headerToken, "Bearer ")
		if len(splitToken) != 2 {
			err = errors.New("token format is not match")
			middleware.Log.Debug(err.Error())
			errorMap["auth"] = err.Error()
			helper.WriteErrorResponse(writer, http.StatusUnauthorized, errorMap)
			return
		}

		secretKey := middleware.Config.String("USER_SECRET_KEY_ACCESS_TOKEN")
		secretKeyByte := []byte(secretKey)

		token, err := jwt.Parse(splitToken[1], func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, http.ErrNotSupported
			}
			return secretKeyByte, nil
		})

		if err != nil {
			if err == jwt.ErrTokenMalformed {
				err = errors.New("token is malformed")
				middleware.Log.Debug(err.Error())
				errorMap["auth"] = err.Error()
				helper.WriteErrorResponse(writer, http.StatusUnauthorized, errorMap)
				return
			} else if err.Error() == "token has invalid claims: token is expired" {
				err = errors.New("token is expired")
				middleware.Log.Debug(err.Error())
				errorMap["auth"] = err.Error()
				helper.WriteErrorResponse(writer, http.StatusUnauthorized, errorMap)
				return
			} else {
				err = errors.New("token is invalid")
				middleware.Log.Debug(err.Error())
				errorMap["auth"] = err.Error()
				helper.WriteErrorResponse(writer, http.StatusUnauthorized, errorMap)
				return
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
				middleware.Log.Debug(err.Error())
				errorMap["auth"] = err.Error()
				helper.WriteErrorResponse(writer, http.StatusUnauthorized, errorMap)
				return
			}
		}

		err = middleware.UserUsecase.CheckUserExistance(request.Context(), userID)
		if err != nil {
			err = errors.New("user not found, please register")
			middleware.Log.Debug(err.Error())
			errorMap["auth"] = err.Error()
			helper.WriteErrorResponse(writer, http.StatusUnauthorized, errorMap)
			return
		}

		middleware.Log.Debug("User:" + userID)

		ctx = context.WithValue(ctx, "user_uuid", userID)
		request = request.WithContext(ctx)

		next(writer, request.WithContext(ctx), params)
	}
}
