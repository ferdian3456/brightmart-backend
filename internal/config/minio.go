package config

import (
	"context"
	"github.com/knadh/koanf/v2"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"go.uber.org/zap"
)

func NewMinio(config *koanf.Koanf, log *zap.Logger) *minio.Client {
	minioClient, err := minio.New(config.String("MINIO_PORT"), &minio.Options{
		Creds:  credentials.NewStaticV4(config.String("MINIO_USER"), config.String("MINIO_PASSWORD"), ""),
		Secure: false,
	})

	if err != nil {
		log.Fatal("Failed to create minio client", zap.Error(err))
	}

	bucketName := config.String("MINIO_BUCKET_NAME")
	location := config.String("MINIO_LOCATION")
	ctx := context.Background()

	err = minioClient.MakeBucket(ctx, bucketName, minio.MakeBucketOptions{
		Region: location,
	})

	if err != nil {
		exists, errBucketExists := minioClient.BucketExists(ctx, bucketName)
		if errBucketExists == nil && exists {

		} else {
			log.Fatal("Failed to make minio bucket: %v", zap.Error(err))
		}
	} else {
		log.Info("Bucket " + bucketName + " is created")
	}

	return minioClient
}
