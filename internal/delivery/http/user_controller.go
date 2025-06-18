package http

import (
	"brightmart-backend/internal/helper"
	"brightmart-backend/internal/model"
	"brightmart-backend/internal/usecase"
	"github.com/julienschmidt/httprouter"
	"github.com/knadh/koanf/v2"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"net/http"
)

type UserController struct {
	UserUsecase  *usecase.UserUsecase
	OAuth2       *oauth2.Config
	Log          *zap.Logger
	Oauth2Config *oauth2.Config
	Config       *koanf.Koanf
}

func NewUserController(userUsecase *usecase.UserUsecase, oauth2 *oauth2.Config, zap *zap.Logger, koanf *koanf.Koanf) *UserController {
	return &UserController{
		UserUsecase: userUsecase,
		OAuth2:      oauth2,
		Log:         zap,
		Config:      koanf,
	}
}

func (controller UserController) MobileRegister(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {
	ctx := request.Context()

	errorMap := map[string]string{}

	payload := model.UserCreateRequest{}
	helper.ReadFromRequestBody(request, &payload)

	err := controller.UserUsecase.Register(ctx, payload, errorMap)
	if err != nil {
		helper.WriteErrorResponse(writer, http.StatusBadRequest, errorMap)
		return
	}

	helper.WriteSuccessResponseNoData(writer)
}

func (controller UserController) MobileUserVerification(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {
	ctx := request.Context()

	errorMap := map[string]string{}

	payload := model.UserVerificationRequest{}
	helper.ReadFromRequestBody(request, &payload)

	response, err := controller.UserUsecase.VerifyUser(ctx, payload, errorMap)
	if err != nil {
		helper.WriteErrorResponse(writer, http.StatusBadRequest, errorMap)
		return
	}

	helper.WriteSuccessResponse(writer, response)
}

func (controller UserController) MobileUserResendCode(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {
	ctx := request.Context()

	errorMap := map[string]string{}

	payload := model.UserResendCodeRequest{}
	helper.ReadFromRequestBody(request, &payload)

	err := controller.UserUsecase.ResendCode(ctx, payload, errorMap)
	if err != nil {
		helper.WriteErrorResponse(writer, http.StatusBadRequest, errorMap)
		return
	}

	helper.WriteSuccessResponseNoData(writer)
}

func (controller UserController) MobileLogin(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {
	ctx := request.Context()

	errorMap := map[string]string{}

	payload := model.UserLoginRequest{}
	helper.ReadFromRequestBody(request, &payload)

	response, err := controller.UserUsecase.Login(ctx, payload, errorMap)
	if err != nil {
		if err["password"] == "wrong email or password" {
			helper.WriteErrorResponse(writer, http.StatusNotFound, err)
			return
		}

		helper.WriteErrorResponse(writer, http.StatusBadRequest, err)
		return
	}

	helper.WriteSuccessResponse(writer, response)
}

func (controller UserController) OAuth(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {
	ctx := request.Context()
	url := controller.UserUsecase.OAuth(ctx)
	http.Redirect(writer, request, url, http.StatusTemporaryRedirect)
}

func (controller UserController) OAuthCallback(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {
	ctx := request.Context()
	
	errorMap := map[string]string{}

	code := request.URL.Query().Get("code")
	state := request.URL.Query().Get("state")

	response, err := controller.UserUsecase.OAuthCallback(ctx, code, state, errorMap)
	if err != nil {
		helper.WriteErrorResponse(writer, http.StatusBadRequest, errorMap)
		return
	}

	helper.WriteSuccessResponse(writer, response)
}
