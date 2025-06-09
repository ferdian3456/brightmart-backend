package config

import (
	"context"
	"github.com/knadh/koanf/v2"
	"go.uber.org/zap"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

func NewPostgresqlPool(config *koanf.Koanf, log *zap.Logger) *pgxpool.Pool {
	dsn := config.String("POSTGRES_URL")
	pgxConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		log.Fatal("Failed to parse postgresl config", zap.Error(err))
	}

	pgxConfig.MaxConns = 50
	pgxConfig.MinConns = 5
	pgxConfig.MaxConnLifetime = 30 * time.Minute
	pgxConfig.MaxConnIdleTime = 5 * time.Minute
	pgxConfig.HealthCheckPeriod = 1 * time.Minute

	pool, err := pgxpool.NewWithConfig(context.Background(), pgxConfig)
	if err != nil {
		log.Fatal("Failed to create pgx pool", zap.Error(err))
	}

	return pool
}
