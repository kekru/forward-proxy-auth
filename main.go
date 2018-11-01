package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/jtblin/go-ldap-client"
	"github.com/kekru/forward-proxy-auth/authenticator"
	"github.com/kekru/forward-proxy-auth/jwtutil"
	"github.com/kekru/forward-proxy-auth/model"

	log "github.com/sirupsen/logrus"

	"github.com/gorilla/mux"
)

type Authenticator interface {
	Authenticate(username string, password string) (user *model.User, err error)
}
type UserResponse struct {
	User       *model.User `json:"user"`
	ExpiryTime string      `json:"expirytime"`
}

var jwtUtil *jwtutil.JwtUtil
var authenticators []Authenticator

func main() {
	log.SetLevel(log.DebugLevel)

	jwtUtil = &jwtutil.JwtUtil{
		ExpireSeconds:  60 * 10,
		HmacSigningKey: []byte("Secret123"),
		Issuer:         "forward-proxy-auth",
	}
	//textfileAuth := &authenticator.TextfileAuth{}
	//authenticators = append(authenticators, textfileAuth)

	ldapAuth := &authenticator.LdapAuth{
		Client: &ldap.LDAPClient{
			Base:         "ou=people,dc=planetexpress,dc=com",
			Host:         "localhost",
			Port:         389,
			UseSSL:       false,
			BindDN:       "cn=admin,dc=planetexpress,dc=com",
			BindPassword: "GoodNewsEveryone",
			UserFilter:   "(uid=%s)",
			GroupFilter:  "(member=cn=%s,ou=people,dc=planetexpress,dc=com)",
			Attributes:   []string{"givenName", "sn", "mail", "uid", "cn"},
		},
		UserNameField:         "uid",
		UserEmailField:        "mail",
		UserNameInGroupsField: "cn",
	}
	authenticators = append(authenticators, ldapAuth)

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/auth", handleAuth)

	log.Fatal(http.ListenAndServe(":8080", router))
}

func writeAuthenticationResponseHeaders(w http.ResponseWriter, user *model.User) {
	w.Header().Set("X-Authenticated-User", user.Name)
	w.Header().Set("X-Authenticated-User-Mail", user.Email)
}

func writeUserResponse(w http.ResponseWriter, user *model.User, expiryTime time.Time) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	userResponse := &UserResponse{
		User:       user,
		ExpiryTime: expiryTime.Format(time.RFC3339),
	}
	json.NewEncoder(w).Encode(userResponse)
}

func getForwardedUri(r *http.Request) string {
	return r.Header.Get("X-Forwarded-Uri")
}

func handleAuth(w http.ResponseWriter, r *http.Request) {

	// try to extraxct user from token
	cookieToken, err := r.Cookie("token")
	if err == nil {
		user, expiryTime, err := jwtUtil.ValidateToken(cookieToken.Value)

		if err == nil {
			writeAuthenticationResponseHeaders(w, user)
			writeUserResponse(w, user, expiryTime)
			return
		}
	}

	if err != nil {
		log.Debug(err)
	}

	// try to login by basic auth credentials
	user, err := login(r)

	if err != nil {
		// no valid credentials, show new basic auth dialog
		log.Debugf("Could not login. %s", err)
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted Area"`)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	// create token for authenticated user
	token, expiryTime, err := jwtUtil.CreateToken(user)

	if err != nil {
		log.Errorf("Could not create token for User %s, %s", user.Name, err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// return token in cookie and redirect on the originally requested uri
	cookie := http.Cookie{
		Name:    "token",
		Value:   token,
		Expires: expiryTime,
	}
	http.SetCookie(w, &cookie)

	forwardedUri := getForwardedUri(r)
	if len(forwardedUri) > 0 {
		log.Debugf("Sending redirect to %s for user %s ", forwardedUri, user.Name)
		http.Redirect(w, r, forwardedUri, http.StatusSeeOther)
	} else {
		writeUserResponse(w, user, expiryTime)
	}

}

func login(r *http.Request) (user *model.User, err error) {
	username, password, authOK := r.BasicAuth()

	if !authOK {
		err = errors.New("no basic auth credentials")
		return
	}

	for _, auth := range authenticators {
		user, err = auth.Authenticate(username, password)
		if err == nil {
			return
		}
	}

	err = errors.New("No user with given username and password found. Username: " + username)
	return
}
