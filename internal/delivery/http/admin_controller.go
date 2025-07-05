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

type AdminController struct {
	AdminUsecase *usecase.AdminUsecase
	OAuth2       *oauth2.Config
	Log          *zap.Logger
	Oauth2Config *oauth2.Config
	Config       *koanf.Koanf
}

func NewAdminController(adminUsecase *usecase.AdminUsecase, oauth2 *oauth2.Config, zap *zap.Logger, koanf *koanf.Koanf) *AdminController {
	return &AdminController{
		AdminUsecase: adminUsecase,
		OAuth2:       oauth2,
		Log:          zap,
		Config:       koanf,
	}
}

func (controller AdminController) WebLoginAdmin(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {
	ctx := request.Context()

	errorMap := map[string]string{}

	payload := model.UserLoginRequest{}
	helper.ReadFromRequestBody(request, payload)

	response, err := controller.AdminUsecase.Login(ctx, payload, errorMap)
	if err != nil {
		if err["password"] == "wrong email or password" {
			helper.WriteErrorResponse(writer, http.StatusNotFound, err)
			return
		}

		helper.WriteErrorResponse(writer, http.StatusBadRequest, err)
		return
	}

	http.SetCookie(writer, &http.Cookie{
		Name:     "access_token",
		Value:    response.Access_token,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		Expires:  response.Access_token_expires_in,
	})

	http.SetCookie(writer, &http.Cookie{
		Name:     "refresh_token",
		Value:    response.Refresh_token,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		Expires:  response.Refresh_token_expires_in,
	})

	helper.WriteSuccessResponseNoData(writer)
}

func (controller AdminController) RefreshRenewal(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {
	ctx := request.Context()

	errorMap := map[string]string{}

	payload := model.RenewalTokenRequest{}
	helper.ReadFromRequestBody(request, &payload)

	response, err := controller.AdminUsecase.RefreshTokenRenewal(ctx, payload, errorMap)
	if err != nil {
		if err["admin"] != "" {
			helper.WriteErrorResponse(writer, http.StatusNotFound, err)
			return
		}

		if err["refresh_token"] == "refresh token reuse detected. for security reasons, you have been logged out. please sign in again." {
			helper.WriteErrorResponse(writer, http.StatusForbidden, err)
			return
		}

		if err["refresh_token"] != "" {
			helper.WriteErrorResponse(writer, http.StatusBadRequest, err)
			return
		}
	}

	helper.WriteSuccessResponse(writer, response)
}

func (controller AdminController) AccessRenewal(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {
	ctx := request.Context()

	errorMap := map[string]string{}

	payload := model.RenewalTokenRequest{}
	helper.ReadFromRequestBody(request, &payload)

	response, err := controller.AdminUsecase.AccessTokenRenewal(ctx, payload, errorMap)
	if err != nil {
		if err["admin"] != "" {
			helper.WriteErrorResponse(writer, http.StatusNotFound, err)
			return
		}

		if err["refresh_token"] == "refresh token reuse detected. for security reasons, you have been logged out. please sign in again." {
			helper.WriteErrorResponse(writer, http.StatusForbidden, err)
			return
		}

		if err["refresh_token"] != "" {
			helper.WriteErrorResponse(writer, http.StatusBadRequest, err)
			return
		}
	}

	helper.WriteSuccessResponse(writer, response)
}

func (controller AdminController) WebCreateAdmin(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {

}

func (controller AdminController) WebGetAllBanner(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {

}

func (controller AdminController) WebGetBannerByID(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {

}

func (controller AdminController) WebCreateBanner(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {

}

func (controller AdminController) WebUpdateBannerByID(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {

}

func (controller AdminController) WebDeleteBannerByID(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {

}

func (controller AdminController) WebGetAllCategory(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {

}

func (controller AdminController) WebGetCategoryByID(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {

}

func (controller AdminController) WebCreateCategory(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {

}

func (controller AdminController) WebUpdateCategoryByID(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {

}

func (controller AdminController) WebDeleteCategoryByID(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {

}

func (controller AdminController) WebGetAllSubCategory(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {

}

func (controller AdminController) WebGetSubCategoryByID(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {

}

func (controller AdminController) WebCreateSubCategory(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {

}

func (controller AdminController) WebUpdateSubCategoryByID(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {

}

func (controller AdminController) WebDeleteSubCategoryByID(writer http.ResponseWriter, request *http.Request, params httprouter.Params) {

}
