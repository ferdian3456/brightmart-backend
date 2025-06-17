package model

import "time"

type RefreshToken struct {
	User_id              string
	Hashed_refresh_token string
	Created_at           time.Time
	Expired_at           time.Time
}
