package main

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"

	//"encoding/base64"
	"github.com/gorilla/mux"
)

type Authenticator interface {
	Authenticate(username string, password string) (user *User, err error)
}

type User struct {
	name   string
	email  string
	groups []string
}

var jwtUtil *JwtUtil
var authenticators []Authenticator

func main() {
	log.SetLevel(log.DebugLevel)

	jwtUtil = &JwtUtil{}
	textfileAuth := &TextfileAuth{}
	authenticators = append(authenticators, textfileAuth)

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/auth", handleAuth)

	log.Fatal(http.ListenAndServe(":8080", router))
}

func extractUser(r *http.Request) (user *User, err error) {
	cookieToken, tokenErr := r.Cookie("token")

	if tokenErr != nil {
		log.Debug("No token cookie ", tokenErr)
		return nil, tokenErr
	}

	return jwtUtil.validate(cookieToken.Value)
}

func writeAuthenticationResponseHeaders(w http.ResponseWriter, user *User) {
	w.Header().Set("X-Authenticated-User", user.name)
	w.Header().Set("X-Authenticated-User-Mail", user.email)
}

func getForwardedUri(r *http.Request) string {
	return r.Header.Get("X-Forwarded-Uri")
}

func handleAuth(w http.ResponseWriter, r *http.Request) {

	// try to extraxct user from token
	user, err := extractUser(r)
	if err == nil {
		writeAuthenticationResponseHeaders(w, user)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// try to login by basic auth credentials
	user, err = login(r)

	if err != nil {
		// no valid credentials, show new basic auth dialog
		log.Debug("Could not login ", err)
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted Area"`)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	// create token for authenticated user
	token, err := jwtUtil.createToken(user)

	if err != nil {
		log.Error("Could not create token", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// return token in cookie and redirect on the originally requested uri
	expire := time.Now().AddDate(0, 0, 1)
	cookie := http.Cookie{
		Name:    "token",
		Value:   token,
		Expires: expire,
	}
	http.SetCookie(w, &cookie)

	forwardedUri := getForwardedUri(r)
	if len(forwardedUri) > 0 {
		log.Debug("Sending redirect to %s for user %s ", forwardedUri, user.name)
		http.Redirect(w, r, forwardedUri, http.StatusSeeOther)
	} else {
		fmt.Fprintln(w, "Welcome %s! Please reload page", user.name)
	}

}

func login(r *http.Request) (user *User, err error) {
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

	err = errors.New("no user with given username and password found. Username " + username)
	return
}
