package helper

import (
	"context"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

func CommitOrRollback(ctx context.Context, tx pgx.Tx, log *zap.Logger) {
	if r := recover(); r != nil { // panic, then rollback then re panic
		err := tx.Rollback(ctx)
		if err != nil {
			log.Fatal("Rollback failed", zap.Error(err))
		}
		panic(r)
	} else { // no panic, commit
		err := tx.Commit(ctx)
		if err != nil {
			log.Fatal("Commit failed", zap.Error(err))
		}
	}
}
