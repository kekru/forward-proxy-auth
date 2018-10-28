package main

import (
	log "github.com/sirupsen/logrus"
)

type TextfileAuth struct {
}

func (textfileAuth *TextfileAuth) Authenticate(username string, password string) (user *User, err error) {

	log.Debug("Username and password ", username, password)

	if username == "admin" && password == "secret" {

		user = &User{
			name:   "admin",
			email:  "admin@example.com",
			groups: []string{"ab", "cd"},
		}
		log.Debug("User ", user)
		err = nil
		return
	}

	err = nil
	user = nil
	return
}
