package model

import "time"

type Admin struct {
	Id        string
	Username  string
	Email     string
	Password  string
	Role      string
	CreatedBy string
	IsActive  string
	CreatedAt time.Time
	UpdatedAt time.Time
}
