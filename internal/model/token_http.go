package model

type RenewalTokenRequest struct {
	Refresh_token string `validate:"required,min=43" json:"refresh_token"`
}

type AccessTokenResponse struct {
	Access_token            string `json:"access_token"`
	Access_token_expires_in int    `json:"access_token_expires_in"`
	Token_type              string `json:"token_type"`
}

type TokenResponse struct {
	Access_token             string `json:"access_token"`
	Access_token_expires_in  int    `json:"access_token_expires_in"`
	Refresh_token            string `json:"refresh_token"`
	Refresh_token_expires_in int    `json:"refresh_token_expires_in"`
	Token_type               string `json:"token_type"`
}
