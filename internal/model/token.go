package model

import "time"

type Token struct {
	Access_token             string
	Refresh_token            string
	Access_token_expires_in  time.Time
	Refresh_token_expires_in time.Time
}
