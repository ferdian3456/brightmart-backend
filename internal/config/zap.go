package config

import "go.uber.org/zap"

func NewZap() *zap.Logger {
	cfg := zap.NewProductionConfig()
	cfg.EncoderConfig.StacktraceKey = ""
	cfg.DisableStacktrace = true

	log, _ := cfg.Build()

	return log
}
