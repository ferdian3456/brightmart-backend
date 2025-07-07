package model

import "time"

type Categories struct {
	Id            string
	Name          string
	CreatedBy     string
	LastUpdatedBy string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}
