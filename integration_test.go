package main

import (
	"net/http"
	"os"
	"os/exec"
	"testing"
)

var client *http.Client

func TestMain(m *testing.M) {
	//defer runCommand("docker-compose", "down")
	//runCommand("docker-compose", "down")
	//	runCommand("docker-compose", "up", "-d")

	client = &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	testResult := m.Run()
	os.Exit(testResult)
}

func TestNoTokenNoPassword(t *testing.T) {

	req, err := http.NewRequest("GET", "http://localhost:8080/auth", nil)
	res, err := client.Do(req)
	if err != nil {
		t.Errorf("failed %s", err)
	}

	if res.StatusCode != 401 {
		t.Logf("unexpected status %v", res.StatusCode)
		t.Fail()
	}
}

func runCommand(name string, arg ...string) {
	cmd := exec.Command(name, arg...)
	cmd.Dir = "./test"
	if err := cmd.Run(); err != nil {
		panic(err)
	}
}
