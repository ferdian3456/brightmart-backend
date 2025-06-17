package model

import "time"

type UserCreateRequest struct {
	Username string `validate:"required|minLen:4|maxLen:22" json:"username"`
	Email    string `validate:"required|minLen:16|maxLen:80" json:"email"`
	Password string `validate:"required|minLen:5|maxLen:20" json:"password"`
}

type UserVerificationRequest struct {
	Code  string `validate:"required|minLen:6|maxLen:6" json:"code"`
	Email string `validate:"required|minLen:16|maxLen:80" json:"email"`
}

type UserResendCodeRequest struct {
	Email string `validate:"required|minLen:16|maxLen:80" json:"email"`
}

type UserLoginRequest struct {
	Email    string `validate:"required|minLen:16|maxLen:80" json:"email"`
	Password string `validate:"required|minLen:5|maxLen:20" json:"password"`
}

type UserUpdateRequest struct {
	Username        string  `validate:"minLen:4|maxLen:22" json:"username"`
	Profile_picture *string `validate:"minLen:49|maxLen:49" json:"profile_picture"`
	Contact_phone   string  `validate:"minLen:7|maxLen:15" json:"contact_phone"`
}

type UserResponse struct {
	Id              string    `json:"id"`
	Username        string    `json:"username"`
	Email           string    `json:"email"`
	Profile_picture *string   `json:"profile_picture"`
	Contact_phone   *string   `json:"contact_phone"`
	Created_at      time.Time `json:"created_at"`
	Updated_at      time.Time `json:"updated_at"`
}
