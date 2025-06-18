package model

import "time"

type User struct {
	Id               string
	Username         string
	Email            string
	Phone_number     *string
	Profile_picture  *string
	Auth_provider    string
	Provider_user_id *string
	Is_verified      bool
	Password         string
	Created_at       time.Time
	Updated_at       time.Time
}
