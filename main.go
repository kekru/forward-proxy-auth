package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"

	"github.com/kekru/forward-proxy-auth/authenticator"
	"github.com/kekru/forward-proxy-auth/jwtutil"
	"github.com/kekru/forward-proxy-auth/model"

	"github.com/go-yaml/yaml"
	log "github.com/sirupsen/logrus"

	"github.com/gorilla/mux"
	"github.com/kelseyhightower/envconfig"
)

type Authenticator interface {
	Authenticate(username string, password string) (user *model.User, err error)
}

type LoginFormData struct {
	LoginUri string
}

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
		Method   string                      `yaml:"Method"`
		Ldap     *authenticator.LdapAuth     `yaml:"Ldap"`
		Textfile *authenticator.TextfileAuth `yaml:"Textfile"`
		OpenId   *authenticator.OpenIdAuth   `yaml:"OpenId"`
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

	authenticators = append(authenticators, config.Authenticator.Ldap)

	log.SetLevel(log.DebugLevel)

	config.Authenticator.OpenId = &authenticator.OpenIdAuth{
		ClientID:     "example-app",
		ClientSecret: "ZXhhbXBsZS1hcHAtc2VjcmV0",
		ProviderURL:  "http://192.168.0.150:5556/dex",
		RedirectURL:  "http://192.168.0.150/fpa/callback",
	}
	config.Authenticator.OpenId.Init()

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/auth", handleAuth)
	router.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		token, expiryTime, err := config.Authenticator.OpenId.HandleCallback(w, r)
		if err != nil {
			http.Error(w, "error occured "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeResponseToken(token, expiryTime, w)
		w.WriteHeader(http.StatusOK)
	})

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
			user, expiryTime, err := validateToken(cookieToken.Value)
			if err == nil {
				return user, expiryTime, err
			}
		}
	}

	for _, headerName := range config.Header.TokenHeaders {
		headerValue := r.Header.Get(headerName)
		if len(headerValue) > 0 {
			user, expiryTime, err := validateToken(headerValue)

			if err == nil {
				return user, expiryTime, err
			}
		}
	}

	return nil, time.Time{}, errors.New("No valid token found")
}

func validateToken(tokenString string) (user *model.User, expiryTime time.Time, err error) {
	method := config.Authenticator.Method
	if method == "basic" || method == "htmlform" {
		return jwtUtil.ValidateToken(tokenString)
	} else if method == "openid" {
		return config.Authenticator.OpenId.ValidateToken(tokenString)
	} else {
		panic("Unknown authentication method: " + method)
	}
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

	// try to login by basic auth credentials
	user, err = login(r)

	forwardedUri := strings.TrimSpace(r.URL.Query().Get("redirect"))
	if len(forwardedUri) == 0 {
		forwardedUri = getForwardedUri(r)
	}

	if err != nil {
		// no valid credentials, show new basic auth dialog
		log.Debugf("Could not login. %s", err)

		method := config.Authenticator.Method
		if method == "basic" {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted Area"`)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		} else if method == "htmlform" {
			writeLoginpage(w, forwardedUri)
		} else if method == "openid" {
			config.Authenticator.OpenId.RedirectToOpenIdProvider(w, r)
			return
		} else {
			log.Errorf("Unknown authentication method: %s", method)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
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
	if len(forwardedUri) > 0 {
		log.Debugf("Sending redirect to %s for user %s ", forwardedUri, user.Name)
		http.Redirect(w, r, forwardedUri, http.StatusSeeOther)
	} else {
		writeUserResponse(w, user, expiryTime)
	}

}

func login(r *http.Request) (user *model.User, err error) {
	var username, password string

	method := config.Authenticator.Method
	if method == "basic" {
		var authOK bool
		username, password, authOK = r.BasicAuth()

		if !authOK {
			err = errors.New("no basic auth credentials")
			return
		}
	} else if method == "htmlform" {
		err = r.ParseForm()
		if err != nil {
			return
		}
		username = strings.TrimSpace(r.Form.Get("username"))
		password = strings.TrimSpace(r.Form.Get("password"))
		if len(username) == 0 && len(password) == 0 {
			err = errors.New("username or password of html form was empty")
			return
		}

	} else {
		err = errors.New("Unknown authentication method: " + method)
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

func writeLoginpage(w http.ResponseWriter, forwardedUri string) {

	t, err := template.ParseFiles("static/login.html")
	if err != nil {
		log.Errorf("could not read static/login.html, %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusUnauthorized)

	templateData := &LoginFormData{
		LoginUri: config.Server.Uri + "/auth?redirect=" + forwardedUri,
	}

	t.Execute(w, templateData)
}
