package model

import "time"

type SubCategories struct {
	Id            string
	Name          string
	CategoryID    int
	CreatedBy     string
	LastUpdatedBy string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}
