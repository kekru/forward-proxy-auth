package base

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"os"
	"os/exec"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type ServiceInfo struct {
	Name    string
	envVars map[string]string
}

func ServiceSetup(setupName string) *ServiceInfo {

	return &ServiceInfo{
		Name:    setupName,
		envVars: make(map[string]string),
	}
}

func (serviceInfo *ServiceInfo) Start() *ServiceInfo {
	serviceInfo.writeEnvFile()
	runCommand("resources/compose/"+serviceInfo.Name, "docker-compose", "up", "-d")
	time.Sleep(800 * time.Millisecond)
	return serviceInfo
}

func (serviceInfo *ServiceInfo) RestartFPA() *ServiceInfo {
	serviceInfo.writeEnvFile()
	runCommand("resources/compose/"+serviceInfo.Name, "docker-compose", "restart", "forward-proxy-auth")
	time.Sleep(200 * time.Millisecond)
	return serviceInfo
}

func (serviceInfo *ServiceInfo) ClearEnv() *ServiceInfo {
	serviceInfo.envVars = make(map[string]string)
	return serviceInfo
}

func (serviceInfo *ServiceInfo) Stop() {
	if os.Getenv("FPA_TEST_KEEP_RUNNING") != "1" {
		runCommand("resources/compose/"+serviceInfo.Name, "docker-compose", "down")
	} else {
		log.Info("Not stopping services, because env var is set: FPA_TEST_KEEP_RUNNING=1")
	}
}

func (serviceInfo *ServiceInfo) Env(key, value string) *ServiceInfo {
	serviceInfo.envVars[key] = value
	return serviceInfo
}

func runCommand(dir string, name string, arg ...string) {
	cmd := exec.Command(name, arg...)
	cmd.Dir = "./" + dir
	out, err := cmd.CombinedOutput()
	log.Infof("Output of command: " + string(out))
	if err != nil {
		panic(err)
	}
}

func (serviceInfo *ServiceInfo) writeEnvFile() {
	file, err := os.Create("resources/compose/" + serviceInfo.Name + "/tmpconfig.env")
	if err != nil {
		log.Fatal("Cannot create file", err)
	}
	defer file.Close()

	for key, value := range serviceInfo.envVars {
		fmt.Fprintf(file, "%s=%s", key, value)
		fmt.Fprintln(file)
	}
}

func CreateClient() (client *http.Client) {
	cookieJar, _ := cookiejar.New(nil)

	return &http.Client{
		Jar: cookieJar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func ReadBodyString(res *http.Response, assert *assert.Assertions) string {
	defer res.Body.Close()
	bodyBytes, err := ioutil.ReadAll(res.Body)
	assert.Nil(err)
	return string(bodyBytes)
}

func ReadBodyJson(res *http.Response, target interface{}, assert *assert.Assertions) {
	defer res.Body.Close()
	bodyBytes, err := ioutil.ReadAll(res.Body)
	assert.Nil(err)
	json.Unmarshal(bodyBytes, target)
}

func Send(req *http.Request, client *http.Client, t *testing.T) (res *http.Response) {
	res, err := client.Do(req)
	printReq(req, t)
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
