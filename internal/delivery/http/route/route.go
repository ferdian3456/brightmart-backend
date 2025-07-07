package route

import (
	"brightmart-backend/internal/delivery/http"
	"brightmart-backend/internal/delivery/http/middleware"
	"github.com/julienschmidt/httprouter"
)

type RouteConfig struct {
	Router          *httprouter.Router
	UserController  *http.UserController
	AdminController *http.AdminController
	AuthMiddleware  *middleware.AuthMiddleware
}

func (c *RouteConfig) SetupRoute() {
	// web
	// admin and superadmin
	c.Router.POST("/api/web/admin/login", c.AdminController.WebLoginAdmin)
	c.Router.POST("/api/web/admin/users", c.AuthMiddleware.WebSuperAdminProtectedMiddleware(c.AdminController.WebCreateAdmin))
	c.Router.POST("/api/web/admin/refresh", c.AdminController.RefreshRenewal)
	c.Router.POST("/api/web/admin/access", c.AdminController.AccessRenewal)

	// banner
	c.Router.GET("/api/web/admin/banners", c.AdminController.WebGetAllBanner)
	c.Router.GET("/api/web/admin/banners/:bannerID", c.AdminController.WebGetBannerByID)
	c.Router.POST("/api/web/admin/banners", c.AuthMiddleware.WebAdminProtectedMiddleware(c.AdminController.WebCreateBanner))
	c.Router.PATCH("/api/web/admin/banners/:bannerID", c.AuthMiddleware.WebAdminProtectedMiddleware(c.AdminController.WebUpdateBannerByID))
	c.Router.DELETE("/api/web/admin/banners/:bannerID", c.AuthMiddleware.WebAdminProtectedMiddleware(c.AdminController.WebDeleteBannerByID))

	// category
	c.Router.GET("/api/web/admin/categories", c.AdminController.WebGetAllCategory)
	c.Router.GET("/api/web/admin/categories/:categoryID", c.AdminController.WebGetCategoryByID)
	c.Router.POST("/api/web/admin/categories", c.AuthMiddleware.WebAdminProtectedMiddleware(c.AdminController.WebCreateCategory))
	c.Router.PATCH("/api/web/admin/categories/:categoryID", c.AuthMiddleware.WebAdminProtectedMiddleware(c.AdminController.WebUpdateCategoryByID))
	c.Router.DELETE("/api/web/admin/categories/:categoryID", c.AuthMiddleware.WebAdminProtectedMiddleware(c.AdminController.WebDeleteCategoryByID))

	// sub category
	c.Router.GET("/api/web/admin/sub-categories", c.AdminController.WebGetAllSubCategory)
	c.Router.GET("/api/web/admin/sub-categories/:subCategoryID", c.AdminController.WebGetSubCategoryByID)
	c.Router.POST("/api/web/admin/sub-categories", c.AuthMiddleware.WebAdminProtectedMiddleware(c.AdminController.WebCreateSubCategory))
	c.Router.PATCH("/api/web/admin/sub-categories/:subCategoryID", c.AuthMiddleware.WebAdminProtectedMiddleware(c.AdminController.WebUpdateSubCategoryByID))
	c.Router.DELETE("/api/web/admin/sub-categories/:subCategoryID", c.AuthMiddleware.WebAdminProtectedMiddleware(c.AdminController.WebDeleteSubCategoryByID))

	// user
	c.Router.POST("/api/web/register", c.UserController.WebRegister)
	c.Router.POST("/api/web/login", c.UserController.WebRegister)

	// mobile
	// user
	c.Router.POST("/api/mobile/register", c.UserController.MobileRegister)
	c.Router.POST("/api/mobile/login", c.UserController.MobileLogin)
	c.Router.POST("/api/mobile/verify", c.UserController.MobileUserVerification)
	c.Router.POST("/api/mobile/refresh", c.UserController.RefreshRenewal)
	c.Router.POST("/api/mobile/access", c.UserController.AccessRenewal)
	c.Router.POST("/api/mobile/resendcode", c.UserController.MobileUserResendCode)
	c.Router.GET("/api/mobile/google/oauth", c.UserController.OAuth)
	c.Router.GET("/api/mobile/google/callback", c.UserController.OAuthCallback)
}
