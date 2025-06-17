package model

import "time"

type User struct {
	Id              string
	Username        string
	Email           string
	Profile_picture *string
	Contact_phone   string
	Password        string
	Created_at      time.Time
	Updated_at      time.Time
}
