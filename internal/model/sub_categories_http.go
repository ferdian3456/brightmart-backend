package model

import "time"

type SubCategoriesResponse struct {
	Id            string    `json:"id"`
	Name          string    `json:"name"`
	CategoryID    int       `json:"category_id"`
	CreatedBy     string    `json:"created_by"`
	LastUpdatedBy string    `json:"last_updated_by"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}
