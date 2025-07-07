package model

import "time"

type Banner struct {
	Id            string
	Name          string
	CreatedBy     string
	LastUpdatedBy string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}
