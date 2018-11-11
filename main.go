package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kekru/forward-proxy-auth/authenticator"
	"github.com/kekru/forward-proxy-auth/jwtutil"
	"github.com/kekru/forward-proxy-auth/model"

	"github.com/go-yaml/yaml"
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

type ForwardAuthConfig struct {
	Version string `yaml:"Version"`

	Server struct {
		Port     int    `yaml:"Port"`
		Loglevel string `yaml:"Loglevel"`
	} `yaml:"Server"`

	Header struct {
		ForwardedUri string `yaml:"ForwardedUri"`

		TokenCookie []string `yaml:"TokenCookie"`
		TokenHeader []string `yaml:"TokenHeader"`

		AuthenticatedUser   []string `yaml:"AuthenticatedUser"`
		AuthenticatedEMail  []string `yaml:"AuthenticatedEMail"`
		AuthenticatedGroups []string `yaml:"AuthenticatedGroups"`
	} `yaml:"Header"`

	Jwt struct {
		ExpireSeconds  int    `yaml:"ExpireSeconds"`
		HmacSigningKey string `yaml:"HmacSigningKey"`
		Issuer         string `yaml:"Issuer"`
	} `yaml:"Jwt"`

	Authenticator struct {
		Ldap     *authenticator.LdapAuth     `yaml:"Ldap"`
		Textfile *authenticator.TextfileAuth `yaml:"Textfile"`
	} `yaml:"Authenticator"`
}

var jwtUtil *jwtutil.JwtUtil
var authenticators []Authenticator
var config *ForwardAuthConfig

func main() {
	log.SetLevel(log.DebugLevel)

	config = &ForwardAuthConfig{}
	bytes, err := ioutil.ReadFile("config.yml")
	if err != nil {
		log.Fatal(err)
	}

	err = yaml.Unmarshal(bytes, config)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	fmt.Println(*config)

	jwtUtil = &jwtutil.JwtUtil{
		ExpireSeconds:  config.Jwt.ExpireSeconds,
		HmacSigningKey: []byte(config.Jwt.HmacSigningKey),
		Issuer:         config.Jwt.Issuer,
	}

	authenticators = append(authenticators, config.Authenticator.Ldap)

	log.SetLevel(log.DebugLevel)

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/auth", handleAuth)

	log.Fatal(http.ListenAndServe(":"+strconv.Itoa(config.Server.Port), router))
}

func writeAuthenticationResponseHeaders(w http.ResponseWriter, user *model.User) {

	for _, header := range config.Header.AuthenticatedUser {
		w.Header().Set(header, user.Name)
	}

	for _, header := range config.Header.AuthenticatedEMail {
		w.Header().Set(header, user.Email)
	}

	for _, header := range config.Header.AuthenticatedGroups {
		w.Header().Set(header, strings.Join(user.Groups, ","))
	}
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
	return r.Header.Get(config.Header.ForwardedUri)
}

func extractUserFromToken(r *http.Request) (user *model.User, expiryTime time.Time, err error) {
	for _, cookieName := range config.Header.TokenCookie {
		cookieToken, err := r.Cookie(cookieName)
		if err == nil {
			user, expiryTime, err := jwtUtil.ValidateToken(cookieToken.Value)
			if err == nil {
				return user, expiryTime, err
			}
		}
	}

	for _, headerName := range config.Header.TokenHeader {
		headerValue := r.Header.Get(headerName)
		if len(headerValue) > 0 {
			user, expiryTime, err := jwtUtil.ValidateToken(headerValue)

			if err == nil {
				return user, expiryTime, err
			}
		}
	}

	return nil, time.Time{}, errors.New("No valid token found")
}

func writeResponseToken(token string, expiryTime time.Time, w http.ResponseWriter) {

	for _, cookieName := range config.Header.TokenCookie {
		cookie := http.Cookie{
			Name:    cookieName,
			Value:   token,
			Expires: expiryTime,
		}
		http.SetCookie(w, &cookie)
	}

	for _, headerName := range config.Header.TokenHeader {
		w.Header().Set(headerName, token)
	}
}

func handleAuth(w http.ResponseWriter, r *http.Request) {

	// try to extraxct user from token
	user, expiryTime, err := extractUserFromToken(r)
	if err == nil {
		writeAuthenticationResponseHeaders(w, user)
		writeUserResponse(w, user, expiryTime)
		return
	}

	if err != nil {
		log.Debug(err)
	}

	// try to login by basic auth credentials
	user, err = login(r)

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

	// return token in cookie
	writeResponseToken(token, expiryTime, w)

	// redirect on the originally requested uri
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
		} else {
			log.Debug(err)
		}
	}

	err = errors.New("No user with given username and password found. Username: " + username)
	return
}
