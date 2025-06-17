package model

type WebResponse struct {
	Status string      `json:"status"`
	Data   interface{} `json:"data"`
}

type TokenResponse struct {
	Access_token             string `json:"access_token"`
	Access_token_expires_in  int    `json:"access_token_expires_in"`
	Refresh_token            string `json:"refresh_token"`
	Refresh_token_expires_in int    `json:"refresh_token_expires_in"`
	Token_type               string `json:"token_type"`
}
