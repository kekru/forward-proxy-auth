package authenticator

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

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

func (auth *OpenIdAuth) HandleCallback(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("state") != state {
		http.Error(w, "state did not match", http.StatusBadRequest)
		return
	}

	oauth2Token, err := auth.config.Exchange(auth.ctx, r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return
	}
	idToken, err := auth.verifier.Verify(auth.ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("idToken %s", idToken)

	//oauth2Token.AccessToken = "*REDACTED*"

	resp := struct {
		OAuth2Token   *oauth2.Token
		IDTokenClaims *json.RawMessage // ID Token payload is just JSON.
	}{oauth2Token, new(json.RawMessage)}

	if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data, err := json.MarshalIndent(resp, "", "    ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(data)

}
