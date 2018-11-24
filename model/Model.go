package model

type User struct {
	Name   string   `json:"name"`
	Email  string   `json:"email"`
	Groups []string `json:"groups"`
}

type UserResponse struct {
	User       *User  `json:"user"`
	ExpiryTime string `json:"expirytime"`
}
