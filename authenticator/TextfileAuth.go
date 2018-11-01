package authenticator

import (
	"github.com/kekru/forward-proxy-auth/model"
	log "github.com/sirupsen/logrus"
)

type TextfileAuth struct {
}

func (textfileAuth *TextfileAuth) Authenticate(username string, password string) (user *model.User, err error) {

	log.Debug("Username and password ", username, password)

	if username == "admin" && password == "secret" {

		user = &model.User{
			Name:   "admin",
			Email:  "admin@example.com",
			Groups: []string{"ab", "cd"},
		}
		log.Debug("User ", user)
		err = nil
		return
	}

	err = nil
	user = nil
	return
}
