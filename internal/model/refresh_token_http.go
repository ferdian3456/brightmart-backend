package model

type RenewalTokenRequest struct {
	Refresh_token string `validate:"required,min=43" json:"refresh_token"`
}
