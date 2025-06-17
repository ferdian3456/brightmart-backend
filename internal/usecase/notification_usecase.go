package usecase

import (
	"brightmart-backend/internal/model"
	"brightmart-backend/internal/repository"
	"bytes"
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/knadh/koanf/v2"
	"go.uber.org/zap"
	"gopkg.in/gomail.v2"
	"html/template"
)

const CONFIG_SMTP_HOST = "smtp.gmail.com"
const CONFIG_SMTP_PORT = 587

type NotificationUsecase struct {
	NotificationRepository *repository.NotificationRepository
	Log                    *zap.Logger
	DB                     *pgxpool.Pool
	Config                 *koanf.Koanf
}

func NewNotificationUsecase(notificationRepository *repository.NotificationRepository, db *pgxpool.Pool, zap *zap.Logger, koanf *koanf.Koanf) *NotificationUsecase {
	return &NotificationUsecase{
		NotificationRepository: notificationRepository,
		DB:                     db,
		Log:                    zap,
		Config:                 koanf,
	}
}

func (usecase *NotificationUsecase) SendRegisterNotification(ctx context.Context, tx pgx.Tx, username string, email string, code string) error {
	notification, err := usecase.NotificationRepository.FindNotificationTemplateById(ctx, tx, 1)
	if err != nil {
		respErr := errors.New("failed to find notification template")
		usecase.Log.Panic(respErr.Error(), zap.Error(err))
	}

	template, err := template.New("emailtemplate").Parse(notification.Template_body)
	if err != nil {
		respErr := errors.New("failed to parse html template")
		usecase.Log.Panic(respErr.Error(), zap.Error(err))
	}

	data := model.EmailNotification{
		Username: username,
		Code:     code,
	}

	var tmpl bytes.Buffer
	err = template.Execute(&tmpl, data)
	if err != nil {
		respErr := errors.New("failed to execute html template")
		usecase.Log.Panic(respErr.Error(), zap.Error(err))
	}

	CONFIG_SENDER_NAME := usecase.Config.String("CONFIG_SENDER_NAME")
	CONFIG_AUTH_EMAIL := usecase.Config.String("CONFIG_AUTH_EMAIL")
	CONFIG_AUTH_PASSWORD := usecase.Config.String("CONFIG_AUTH_PASSWORD")

	mailer := gomail.NewMessage()
	mailer.SetHeader("From", CONFIG_SENDER_NAME)
	mailer.SetHeader("To", email)
	mailer.SetHeader("Subject", notification.Template_subject)
	mailer.SetBody("text/html", tmpl.String())

	dialer := gomail.NewDialer(
		CONFIG_SMTP_HOST,
		CONFIG_SMTP_PORT,
		CONFIG_AUTH_EMAIL,
		CONFIG_AUTH_PASSWORD,
	)

	err = dialer.DialAndSend(mailer)
	if err != nil {
		respErr := errors.New("failed to send register notification")
		usecase.Log.Panic(respErr.Error(), zap.Error(err))
	}

	return nil
}
