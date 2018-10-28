package main

import (
	log "github.com/sirupsen/logrus"
)

type JwtUtil struct {
}

func (jwtUtil *JwtUtil) validate(token string) (user *User, err error) {

	log.Debug("validate token ", token)

	user = &User{
		name:   token,
		email:  "admin@example.com",
		groups: []string{"ab", "cd"},
	}

	err = nil
	return
}

func (jwtUtil *JwtUtil) createToken(user *User) (token string, err error) {

	return user.name, nil
}
