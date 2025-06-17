package repository

import (
	"brightmart-backend/internal/model"
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

type NotificationRepository struct {
	Log *zap.Logger
	DB  *pgxpool.Pool
}

func NewNotificationRepository(zap *zap.Logger, db *pgxpool.Pool) *NotificationRepository {
	return &NotificationRepository{
		Log: zap,
		DB:  db,
	}
}

func (repository *NotificationRepository) FindNotificationTemplateById(ctx context.Context, tx pgx.Tx, templateid int) (model.Notification, error) {
	query := "SELECT template_subject,template_body FROM notifications WHERE id=$1"

	notification := model.Notification{}

	err := tx.QueryRow(ctx, query, templateid).Scan(&notification.Template_subject, &notification.Template_body)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return notification, errors.New("notification template not found")
		}
		repository.Log.Panic("failed to query database", zap.Error(err))
	}

	return notification, nil
}
