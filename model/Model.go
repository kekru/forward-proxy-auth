package model

import (
	"net/http"
	"time"
)

type User struct {
	Name   string   `json:"name"`
	Email  string   `json:"email"`
	Groups []string `json:"groups"`
}

type UserResponse struct {
	User       *User  `json:"user"`
	ExpiryTime string `json:"expirytime"`
}

type CredentialAuthenticator interface {
	Authenticate(username string, password string) (user *User, err error)
}

type AuthService interface {
	ValidateToken(tokenString string) (user *User, expiryTime time.Time, err error)
	EvaluateLogin(r *http.Request) (user *User, tokenString string, expiryTime time.Time, err error)
	ServeLoginform(w http.ResponseWriter, r *http.Request)
}

type CredentialProvider interface {
	ReadCredentials(r *http.Request) (username string, password string, err error)
	ServeLoginform(w http.ResponseWriter, r *http.Request)
}
