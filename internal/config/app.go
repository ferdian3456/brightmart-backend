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
	"github.com/minio/minio-go/v7"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

type ServerConfig struct {
	Router   *httprouter.Router
	DB       *pgxpool.Pool
	DBCache  *redis.ClusterClient
	ObjectDB *minio.Client
	Log      *zap.Logger
	OAuth2   *oauth2.Config
	Config   *koanf.Koanf
}

func Server(config *ServerConfig) {
	notificationRepository := repository.NewNotificationRepository(config.Log, config.DB)
	notificationUsecase := usecase.NewNotificationUsecase(notificationRepository, config.DB, config.Log, config.Config)

	userRepository := repository.NewUserRepository(config.Log, config.DB, config.DBCache)
	userUsecase := usecase.NewUserUsecase(notificationUsecase, userRepository, config.DB, config.OAuth2, config.Log, config.Config)
	userController := http.NewUserController(userUsecase, config.OAuth2, config.Log, config.Config)

	adminRepository := repository.NewAdminRepository(config.Log, config.DB, config.DBCache)
	adminUsecase := usecase.NewAdminUsecase(adminRepository, config.DB, config.OAuth2, config.Log, config.Config)
	adminController := http.NewAdminController(adminUsecase, config.OAuth2, config.Log, config.Config)

	authMiddleware := middleware.NewAuthMiddleware(config.Router, config.Log, config.Config, userUsecase, adminUsecase)

	routeConfig := route.RouteConfig{
		Router:          config.Router,
		UserController:  userController,
		AdminController: adminController,
		AuthMiddleware:  authMiddleware,
	}

	routeConfig.SetupRoute()
}
