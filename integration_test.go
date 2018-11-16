package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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
// And Forwarded Uri is set
// Then 303 is returned and cookie is set
func TestBasicAuthLogin(t *testing.T) {
	assert := assert.New(t)

	client := createClient()
	req, _ := http.NewRequest("GET", "http://localhost:8080/auth", nil)
	req.Header.Add("X-Forwarded-Uri", "http://myapp.example.com/any/page")
	req.SetBasicAuth("bender", "bender")

	res := send(req, client, t)

	assert.Equal(303, res.StatusCode)
	assert.Equal("http://myapp.example.com/any/page", res.Header.Get("Location"))

	cookies := res.Cookies()
	if assert.Len(cookies, 1) {
		assert.Equal("token", cookies[0].Name)
		assert.NotEmpty(cookies[0].Value)
	}
}

// Given: authentication is already performed
// When sending token
// And Forwarded Uri is set
// Then 200 is returned with user information
func TestSendValidToken(t *testing.T) {
	assert := assert.New(t)

	client := createClient()

	// Given
	sendBasicAuthLogin(client, t)

	// When
	req, _ := http.NewRequest("GET", "http://localhost:8080/auth", nil)
	res := send(req, client, t)

	// Then
	assert.Equal(200, res.StatusCode)
	defer res.Body.Close()
	bodyBytes, err := ioutil.ReadAll(res.Body)
	assert.Nil(err)

	userRes := &UserResponse{}
	json.Unmarshal(bodyBytes, userRes)

	assert.Equal("bender", userRes.User.Name)
	assert.Equal("bender@planetexpress.com", userRes.User.Email)
	if assert.Len(userRes.User.Groups, 1) {
		assert.Equal(userRes.User.Groups[0], "ship_crew")
	}

	expectedExpiryTime := time.Now().UTC().Add(time.Minute * time.Duration(10))
	actualExpiryTime, err := time.Parse(time.RFC3339, userRes.ExpiryTime)
	assert.Nil(err)
	assert.WithinDuration(expectedExpiryTime, actualExpiryTime, time.Second*5)
}

func createClient() (client *http.Client) {
	cookieJar, _ := cookiejar.New(nil)

	return &http.Client{
		Jar: cookieJar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func sendBasicAuthLogin(client *http.Client, t *testing.T) (res *http.Response) {
	req, _ := http.NewRequest("GET", "http://localhost:8080/auth", nil)
	req.Header.Add("X-Forwarded-Uri", "http://myapp.example.com/any/page")
	req.SetBasicAuth("bender", "bender")

	return send(req, client, t)
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
