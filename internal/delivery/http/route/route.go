package route

import (
	"brightmart-backend/internal/delivery/http"
	"brightmart-backend/internal/delivery/http/middleware"
	"github.com/julienschmidt/httprouter"
)

type RouteConfig struct {
	Router         *httprouter.Router
	UserController *http.UserController
	AuthMiddleware *middleware.AuthMiddleware
}

func (c *RouteConfig) SetupRoute() {
	// web
	//c.Router.POST("/api/web/register", c.UserController.WebRegister)
	//c.Router.POST("/api/web/login", c.UserController.WebRegister)

	// mobile
	c.Router.POST("/api/mobile/register", c.UserController.MobileRegister)
	c.Router.POST("/api/mobile/login", c.UserController.MobileLogin)
	c.Router.POST("/api/mobile/verify", c.UserController.MobileUserVerification)
	c.Router.POST("/api/mobile/resendcode", c.UserController.MobileUserResendCode)
	c.Router.GET("/api/mobile/google/oauth", c.UserController.OAuth)
	c.Router.GET("/api/mobile/google/callback", c.UserController.OAuthCallback)
}
