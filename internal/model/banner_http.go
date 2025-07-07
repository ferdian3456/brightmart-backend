package model

import "time"

type BannerResponse struct {
	Id            string    `json:"id"`
	Name          string    `json:"name"`
	CreatedBy     string    `json:"created_by"`
	LastUpdatedBy string    `json:"last_updated_by"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}
