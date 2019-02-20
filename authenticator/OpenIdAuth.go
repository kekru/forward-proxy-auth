package authenticator

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/kekru/forward-proxy-auth/model"
	log "github.com/sirupsen/logrus"

	oidc "github.com/coreos/go-oidc"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"

	"math/rand"
)

type OpenIdAuth struct {
	ClientID     string `yaml:"ClientID"`
	ClientSecret string `yaml:"ClientSecret"`
	ProviderURL  string `yaml:"ProviderURL"`
	RedirectURL  string `yaml:"RedirectURL"`

	verifier *oidc.IDTokenVerifier
	config   oauth2.Config
	ctx      context.Context
}

var (
	state string // TODO make it unique per user session
)

func (auth *OpenIdAuth) Init() {
	rand.Seed(time.Now().UnixNano())

	auth.ctx = context.Background() // TODO need context per user?

	provider, err := oidc.NewProvider(auth.ctx, auth.ProviderURL)
	if err != nil {
		log.Fatal("server not found ", err)
	}
	oidcConfig := &oidc.Config{
		ClientID: auth.ClientID,
	}
	auth.verifier = provider.Verifier(oidcConfig)

	auth.config = oauth2.Config{
		ClientID:     auth.ClientID,
		ClientSecret: auth.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  auth.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups"}, // "offline_access" for refresh token
	}

	state = strconv.Itoa(rand.Intn(10000000000))

}

func (auth *OpenIdAuth) RedirectToOpenIdProvider(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, auth.config.AuthCodeURL(state), http.StatusFound)
}

func (auth *OpenIdAuth) HandleCallback(w http.ResponseWriter, r *http.Request) (tokenString string, expiryTime time.Time, err error) {
	if r.URL.Query().Get("state") != state {
		return "", time.Time{}, errors.New("state did not match")
	}

	oauth2Token, err := auth.config.Exchange(auth.ctx, r.URL.Query().Get("code"))
	if err != nil {
		return "", time.Time{}, err
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return "", time.Time{}, errors.New("no id_token field in oauth2 token")
	}

	_, expiryTime, err = auth.ValidateToken(rawIDToken)

	return rawIDToken, expiryTime, err
}

func (auth *OpenIdAuth) ValidateToken(tokenString string) (user *model.User, expiryTime time.Time, err error) {

	idToken, err := auth.verifier.Verify(auth.ctx, tokenString)
	if err != nil {
		return nil, time.Time{}, err
	}

	user = &model.User{}
	err = idToken.Claims(&user) // fill user data. Works, because fields of User match the OpenId fields
	if err != nil {
		return nil, time.Time{}, err
	}

	return user, idToken.Expiry, nil
}
