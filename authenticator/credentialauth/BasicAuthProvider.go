package credentialauth

import (
	"errors"
	"net/http"
)

type BasicAuthProvider struct {
}

func (provider *BasicAuthProvider) ReadCredentials(r *http.Request) (username string, password string, err error) {
	var authOK bool
	username, password, authOK = r.BasicAuth()

	if !authOK {
		err = errors.New("no basic auth credentials")
	}
	return
}

func (provider *BasicAuthProvider) ServeLoginform(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", `Basic realm="Restricted Area"`)
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}
