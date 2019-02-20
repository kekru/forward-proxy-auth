package credentialauth

import (
	"errors"
	"net/http"
	"time"

	"github.com/kekru/forward-proxy-auth/jwtutil"
	"github.com/kekru/forward-proxy-auth/model"
	log "github.com/sirupsen/logrus"
)

type CredentialAuth struct {
	JwtUtil                 *jwtutil.JwtUtil
	CredentialProvider      model.CredentialProvider
	CredentialAuthenticator []model.CredentialAuthenticator
}

func (auth *CredentialAuth) ValidateToken(tokenString string) (user *model.User, expiryTime time.Time, err error) {
	return auth.JwtUtil.ValidateToken(tokenString)
}

func (auth *CredentialAuth) EvaluateLogin(r *http.Request) (user *model.User, tokenString string, expiryTime time.Time, err error) {

	username, password, err := auth.CredentialProvider.ReadCredentials(r)
	if err != nil {
		return
	}

	for _, credentialAuthenticator := range auth.CredentialAuthenticator {
		user, err = credentialAuthenticator.Authenticate(username, password)
		if err == nil {
			break // user found
		} else {
			log.Debug(err)
		}
	}

	if user == nil {
		err = errors.New("No user with given username and password found. Username: " + username)
		return
	}

	tokenString, expiryTime, err = auth.JwtUtil.CreateToken(user)
	return
}

func (auth *CredentialAuth) ServeLoginform(w http.ResponseWriter, r *http.Request) {
	auth.CredentialProvider.ServeLoginform(w, r)
}
