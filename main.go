package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"

	"github.com/kekru/forward-proxy-auth/authenticator/credentialauth"
	"github.com/kekru/forward-proxy-auth/authenticator/openid"
	"github.com/kekru/forward-proxy-auth/jwtutil"
	"github.com/kekru/forward-proxy-auth/model"

	"github.com/go-yaml/yaml"
	log "github.com/sirupsen/logrus"

	"github.com/gorilla/mux"
	"github.com/kelseyhightower/envconfig"
)

type ForwardAuthConfig struct {
	Version string `yaml:"Version"`

	Server struct {
		Uri      string `yaml:"Uri"`
		Port     int    `yaml:"Port"`
		Loglevel string `yaml:"Loglevel"`
	} `yaml:"Server"`

	Header struct {
		ForwardedUri string `yaml:"ForwardedUri"`

		TokenCookie struct {
			Names      []string `yaml:"Names"`
			Domain     string   `yaml:"Domain"`
			Path       string   `yaml:"Path"`
			Secure     bool     `yaml:"Secure"`
			HttpOnly   bool     `yaml:"HttpOnly"`
			SameSite   bool     `yaml:"SameSite"`
			Persistent bool     `yaml:"Persistent"`
		} `yaml:"TokenCookie"`
		TokenHeaders []string `yaml:"TokenHeaders"`

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
		Method   string                                 `yaml:"Method"`
		Ldap     *credentialauth.CredentialAuthLdap     `yaml:"Ldap"`
		Textfile *credentialauth.CredentialAuthTextfile `yaml:"Textfile"`
		OpenId   *openid.OpenIdAuth                     `yaml:"OpenId"`
	} `yaml:"Authenticator"`
}

var jwtUtil *jwtutil.JwtUtil
var config *ForwardAuthConfig
var auth model.AuthService

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

	err = envconfig.Process("fpa", config)
	if err != nil {
		log.Fatal(err.Error())
	}
	fmt.Println(*config)

	jwtUtil = &jwtutil.JwtUtil{
		ExpireSeconds:  config.Jwt.ExpireSeconds,
		HmacSigningKey: []byte(config.Jwt.HmacSigningKey),
		Issuer:         config.Jwt.Issuer,
	}

	var authenticators []model.CredentialAuthenticator

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/auth", handleAuth)

	method := config.Authenticator.Method
	if method == "basic" {
		authenticators = append(authenticators, config.Authenticator.Ldap)

		auth = &credentialauth.CredentialAuth{
			CredentialProvider:      &credentialauth.BasicAuthProvider{},
			CredentialAuthenticator: authenticators,
			JwtUtil:                 jwtUtil,
		}
	} else if method == "htmlform" {
		authenticators = append(authenticators, config.Authenticator.Ldap)

		auth = &credentialauth.CredentialAuth{
			CredentialProvider:      &credentialauth.HtmlFormProvider{},
			CredentialAuthenticator: authenticators,
			JwtUtil:                 jwtUtil,
		}

	} else if method == "openid" {

		openIdAuth := &openid.OpenIdAuth{
			ClientID:     "example-app",
			ClientSecret: "ZXhhbXBsZS1hcHAtc2VjcmV0",
			ProviderURL:  "http://192.168.0.150:5556/dex",
			RedirectURL:  "http://192.168.0.150/fpa/callback",
		}
		auth = openIdAuth
		openIdAuth.Init()
		router.HandleFunc("/callback", handleAuth)

	} else {
		log.Fatalf("Unknown authentication method: %s", method)
	}

	log.SetLevel(log.DebugLevel)

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
	userResponse := &model.UserResponse{
		User:       user,
		ExpiryTime: expiryTime.Format(time.RFC3339),
	}
	json.NewEncoder(w).Encode(userResponse)
}

func getForwardedUri(r *http.Request) string {

	forwardedUri := ""
	headers := strings.Split(config.Header.ForwardedUri, "+")
	for _, h := range headers {
		forwardedUri += r.Header.Get(h)
	}

	forwardedUri = strings.TrimSpace(forwardedUri)

	forwardedUriLower := strings.ToLower(forwardedUri)
	if !strings.HasPrefix(forwardedUriLower, "http://") && !strings.HasPrefix(forwardedUriLower, "https://") {
		scheme := r.Header.Get("X-Forwarded-Proto")
		if scheme == "" {
			scheme = "http"
		}

		if !strings.HasSuffix(scheme, "://") {
			scheme = scheme + "://"
		}

		forwardedUri = scheme + forwardedUri
	}

	return forwardedUri
}

func extractUserFromToken(r *http.Request) (user *model.User, expiryTime time.Time, err error) {
	for _, cookieName := range config.Header.TokenCookie.Names {
		cookieToken, err := r.Cookie(cookieName)
		if err == nil {
			user, expiryTime, err := auth.ValidateToken(cookieToken.Value)
			if err == nil {
				return user, expiryTime, err
			}
		}
	}

	for _, headerName := range config.Header.TokenHeaders {
		headerValue := r.Header.Get(headerName)
		if len(headerValue) > 0 {
			user, expiryTime, err := auth.ValidateToken(headerValue)

			if err == nil {
				return user, expiryTime, err
			}
		}
	}

	return nil, time.Time{}, errors.New("No valid token found")
}

func writeResponseToken(token string, expiryTime time.Time, w http.ResponseWriter) {

	cookieMaxAge := 0
	if config.Header.TokenCookie.Persistent {
		cookieMaxAge = int(expiryTime.Unix() - time.Now().Unix())
	}

	var sameSite http.SameSite
	if config.Header.TokenCookie.SameSite {
		sameSite = http.SameSiteStrictMode
	} else {
		sameSite = http.SameSiteLaxMode
	}

	for _, cookieName := range config.Header.TokenCookie.Names {
		cookie := http.Cookie{
			Name:     cookieName,
			Value:    token,
			SameSite: sameSite,
			MaxAge:   cookieMaxAge,
			HttpOnly: config.Header.TokenCookie.HttpOnly,
			Secure:   config.Header.TokenCookie.Secure,
			Domain:   config.Header.TokenCookie.Domain,
			Path:     config.Header.TokenCookie.Path,
		}
		http.SetCookie(w, &cookie)
	}

	for _, headerName := range config.Header.TokenHeaders {
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

	} else {
		log.Debug(err)
	}

	requestDump, err := httputil.DumpRequest(r, true)
	if err == nil {
		log.Debugf("Request\n%s", string(requestDump))
	}

	user, token, expiryTime, err := auth.EvaluateLogin(r)

	// TODO
	//	forwardedUri := strings.TrimSpace(r.URL.Query().Get("redirect"))
	//	if len(forwardedUri) == 0 {
	//		forwardedUri = getForwardedUri(r)
	//	}

	if err != nil {
		// no valid credentials, show new basic auth dialog
		log.Debugf("Could not login. %s", err)
		auth.ServeLoginform(w, r)
		return
	}

	// return token in cookie
	writeResponseToken(token, expiryTime, w)

	// TODO
	// redirect on the originally requested uri
	//if len(forwardedUri) > 0 {
	//		log.Debugf("Sending redirect to %s for user %s ", forwardedUri, user.Name)
	//		http.Redirect(w, r, forwardedUri, http.StatusSeeOther)
	//	} else {
	writeUserResponse(w, user, expiryTime)
	//	}

}
