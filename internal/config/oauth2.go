package config

import (
	"github.com/knadh/koanf/v2"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func NewOAuth2(config *koanf.Koanf) *oauth2.Config {
	oAuth2Config := &oauth2.Config{
		ClientID:     config.String("OAUTH_CLIENT_ID"),
		ClientSecret: config.String("OAUTH_CLIENT_SECRET"),
		RedirectURL:  config.String("OAUTH_REDIRECT_URL"),
		Scopes:       []string{"email", "profile"},
		Endpoint:     google.Endpoint,
	}

	return oAuth2Config
}
