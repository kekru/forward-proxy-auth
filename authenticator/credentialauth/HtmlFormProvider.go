package credentialauth

import (
	"errors"
	"html/template"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
)

type HtmlFormProvider struct {
}

type loginFormData struct {
	LoginUri string
}

func (provider *HtmlFormProvider) ReadCredentials(r *http.Request) (username string, password string, err error) {
	err = r.ParseForm()
	if err != nil {
		return
	}
	username = strings.TrimSpace(r.Form.Get("username"))
	password = strings.TrimSpace(r.Form.Get("password"))
	if len(username) == 0 && len(password) == 0 {
		err = errors.New("username or password of html form was empty")
	}
	return
}

func (provider *HtmlFormProvider) ServeLoginform(w http.ResponseWriter, r *http.Request) {

	t, err := template.ParseFiles("static/login.html")
	if err != nil {
		log.Errorf("could not read static/login.html, %s", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusUnauthorized)

	templateData := &loginFormData{
		LoginUri: "", // TODO config.Server.Uri + "/auth?redirect="+ forwardedUri,
	}

	t.Execute(w, templateData)
}
