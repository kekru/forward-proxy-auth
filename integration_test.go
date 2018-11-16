package main

import (
	"net/http"
	"net/http/httputil"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// When to token and no login/password are sent
// Then 401 is returned
func TestNoTokenNoPassword(t *testing.T) {
	assert := assert.New(t)

	client := createClient()
	req, _ := http.NewRequest("GET", "http://localhost:8080/auth", nil)
	res := send(req, client, t)

	assert.Equal(401, res.StatusCode)
	assert.Equal(0, len(res.Cookies()))
}

// When to token, but correct Basic Auth is sent
// And Forawrded Uri is set
// Then 303 is returned
func TestBasicAuthLogin(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	client := createClient()
	req, _ := http.NewRequest("GET", "http://localhost:8080/auth", nil)
	req.Header.Add("X-Forwarded-Uri", "http://myapp.example.com/any/page")
	req.SetBasicAuth("bender", "bender")
	res := send(req, client, t)

	assert.Equal(303, res.StatusCode)

	assert.Equal("http://myapp.example.com/any/page", res.Header.Get("Location"))

	cookies := res.Cookies()

	require.Equal(len(cookies), 1)
	assert.Equal("token", cookies[0].Name)
}

func createClient() (client *http.Client) {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func send(req *http.Request, client *http.Client, t *testing.T) (res *http.Response) {
	printReq(req, t)
	res, err := client.Do(req)
	printRes(res, t)
	if err != nil {
		t.Errorf("failed %s", err)
	}

	return res
}

func printReq(req *http.Request, t *testing.T) {
	requestDump, err := httputil.DumpRequestOut(req, true)
	if err == nil {
		t.Logf("Request\n%s", string(requestDump))
	} else {
		t.Errorf("failed to print request %v", err)
	}
}

func printRes(res *http.Response, t *testing.T) {
	responseDump, err := httputil.DumpResponse(res, true)
	if err == nil {
		t.Logf("Response\n%s", string(responseDump))
	} else {
		t.Errorf("failed to print response %v", err)
	}
}
