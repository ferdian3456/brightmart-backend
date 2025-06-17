package config

import (
	"brightmart-backend/internal/delivery/http"
	"brightmart-backend/internal/delivery/http/middleware"
	"brightmart-backend/internal/delivery/http/route"
	"brightmart-backend/internal/repository"
	"brightmart-backend/internal/usecase"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/julienschmidt/httprouter"
	"github.com/knadh/koanf/v2"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

type ServerConfig struct {
	Router       *httprouter.Router
	DB           *pgxpool.Pool
	DBCache      *redis.ClusterClient
	Log          *zap.Logger
	OAuth2Config *oauth2.Config
	Config       *koanf.Koanf
}

func Server(config *ServerConfig) {
	notificationRepository := repository.NewNotificationRepository(config.Log, config.DB)
	notificationUsecase := usecase.NewNotificationUsecase(notificationRepository, config.DB, config.Log, config.Config)

	userRepository := repository.NewUserRepository(config.Log, config.DB, config.DBCache)
	userUsecase := usecase.NewUserUsecase(notificationUsecase, userRepository, config.DB, config.Log, config.Config)
	userController := http.NewUserController(userUsecase, config.Log, config.Config)

	authMiddleware := middleware.NewAuthMiddleware(config.Router, config.Log, config.Config, userUsecase)

	routeConfig := route.RouteConfig{
		Router:         config.Router,
		UserController: userController,
		AuthMiddleware: authMiddleware,
	}

	routeConfig.SetupRoute()
}
