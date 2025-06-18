package main

import (
	"brightmart-backend/internal/config"
	"brightmart-backend/internal/exception"
	"context"
	zapLog "go.uber.org/zap"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Access-Control-Allow-Origin", "*")
		writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		writer.Header().Set("Access-Control-Allow-Headers", "X-Requested-With, Content-Type, Authorization")
		writer.Header().Set("Access-Control-Allow-Credentials", "True")
		if request.Method == http.MethodOptions {
			writer.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(writer, request)
	})
}

func main() {
	// Flush zap buffered log first then cancel the context for graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	httprouter := config.NewHttpRouter()
	zap := config.NewZap()
	koanf := config.NewKoanf(zap)
	rds := config.NewRedisCluster(koanf, zap)
	postgresql := config.NewPostgresqlPool(koanf, zap)
	oAUth2 := config.NewOAuth2(koanf)

	config.Server(&config.ServerConfig{
		Router:  httprouter,
		DB:      postgresql,
		DBCache: rds,
		Log:     zap,
		OAuth2:  oAUth2,
		Config:  koanf,
	})

	httprouter.PanicHandler = exception.ErrorHandler

	GO_SERVER_PORT := koanf.String("GO_SERVER")

	server := http.Server{
		Addr:    GO_SERVER_PORT,
		Handler: CORS(httprouter),
	}

	zap.Info("Server is running on: " + GO_SERVER_PORT)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			zap.Fatal("Error Starting Server", zapLog.Error(err))
		}
	}()

	<-stop
	zap.Info("Got one of stop signals")

	if err := server.Shutdown(ctx); err != nil {
		zap.Warn("Timeout, forced kill!", zapLog.Error(err))
		zap.Sync()
		os.Exit(1)
	}

	zap.Info("Server has shut down gracefully")
	zap.Sync()
}
