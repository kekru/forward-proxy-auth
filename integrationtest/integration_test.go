package integrationtest

import (
	"net/http"
	"os"
	"testing"
	"time"

	it "github.com/kekru/forward-proxy-auth/integrationtest/base"
	"github.com/kekru/forward-proxy-auth/model"
	"github.com/stretchr/testify/assert"
)

var serviceInfo *it.ServiceInfo

func TestMain(m *testing.M) {
	serviceInfo = it.ServiceSetup("base-ldap").Start()

	testResult := m.Run()

	serviceInfo.Stop()
	os.Exit(testResult)
}

// When to token and no login/password are sent
// Then 401 is returned
func TestNoTokenNoPassword(t *testing.T) {
	assert := assert.New(t)

	client := it.CreateClient()
	req, _ := http.NewRequest("GET", "http://localhost:8080/auth", nil)
	res := it.Send(req, client, t)

	assert.Equal(401, res.StatusCode)
	assert.Equal(0, len(res.Cookies()))
}

// When to token, but correct Basic Auth is sent
// And Forwarded Uri is set
// Then 303 is returned and cookie is set
func TestBasicAuthLogin(t *testing.T) {
	assert := assert.New(t)

	client := it.CreateClient()
	req, _ := http.NewRequest("GET", "http://localhost:8080/auth", nil)
	req.Header.Add("X-Forwarded-Uri", "http://myapp.example.com/any/page")
	req.SetBasicAuth("bender", "bender")

	res := it.Send(req, client, t)

	assert.Equal(303, res.StatusCode)
	assert.Equal("http://myapp.example.com/any/page", res.Header.Get("Location"))

	cookies := res.Cookies()
	if assert.Len(cookies, 1) {
		cookie := cookies[0]
		assert.Equal("token", cookie.Name)
		assert.NotEmpty(cookie.Value)

		assert.Equal(10*60, cookie.MaxAge)
		assert.Equal(true, cookie.HttpOnly)
		assert.Equal(http.SameSiteStrictMode, cookie.SameSite)
		assert.Equal(false, cookie.Secure)
		assert.Equal("localhost", cookie.Domain)
		assert.Equal("/", cookie.Path)
	}
}

// Given: authentication is already performed
// When sending token
// And Forwarded Uri is set
// Then 200 is returned with user information
func TestSendValidToken(t *testing.T) {
	assert := assert.New(t)

	client := it.CreateClient()

	// Given
	sendBasicAuthLogin(client, t)

	// When
	req, _ := http.NewRequest("GET", "http://localhost:8080/auth", nil)
	res := it.Send(req, client, t)

	// Then
	assert.Equal(200, res.StatusCode)
	userRes := &model.UserResponse{}
	it.ReadBodyJson(res, userRes, assert)

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

// Given: authentication is already performed
// When sending a maipulated token
// Then 403 is returned
func TestSendManipulatedToken(t *testing.T) {
	assert := assert.New(t)

	client := it.CreateClient()

	// Given
	res := sendBasicAuthLogin(client, t)
	cookies := res.Cookies()
	assert.Len(cookies, 1)
	tokenCookie := cookies[0]
	assert.Equal("token", tokenCookie.Name)
	assert.NotEqual("x", tokenCookie.Value[0])

	// When
	req, _ := http.NewRequest("GET", "http://localhost:8080/auth", nil)
	tokenCookie.Value = "x" + tokenCookie.Value[1:]

	client.Jar.SetCookies(req.URL, []*http.Cookie{tokenCookie})
	res = it.Send(req, client, t)

	// Then
	assert.Equal(401, res.StatusCode)
	assert.Equal("Unauthorized\n", it.ReadBodyString(res, assert))
}

func sendBasicAuthLogin(client *http.Client, t *testing.T) (res *http.Response) {
	req, _ := http.NewRequest("GET", "http://localhost:8080/auth", nil)
	req.Header.Add("X-Forwarded-Uri", "http://myapp.example.com/any/page")
	req.SetBasicAuth("bender", "bender")

	return it.Send(req, client, t)
}
