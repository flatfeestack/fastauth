package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"
)

const (
	testDBPath = "/tmp"
	testDomain = "localhost"
	testUrl    = "http://" + testDomain + ":8081"
)

/*
curl -v "http://localhost:8080/signin"   -X POST   -d "{\"email\":\"tom\",\"password\":\"test\"}"   -H "Content-Type: application/json"
*/
func TestSignin(t *testing.T) {
	s, c := server(&Opts{Port: 8081, DBPath: testDBPath, Url: testUrl + "/send/email/{email}/{token}"})
	resp := doSignin("tom@test.ch", "testtest")

	assert.Equal(t, 200, resp.StatusCode)

	defer resp.Body.Close()
	s.Shutdown(context.Background())
	<-c
}

func TestSigninWrongEmail(t *testing.T) {
	s, c := server(&Opts{Port: 8081, DBPath: testDBPath, Url: testUrl + "/send/email/{email}/{token}"})
	resp := doSignin("tomtest.ch", "testtest")

	assert.Equal(t, 400, resp.StatusCode)
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	bodyString := string(bodyBytes)
	assert.Equal(t, 0, strings.Index(bodyString, "SI02"))

	defer resp.Body.Close()
	s.Shutdown(context.Background())
	<-c
}

func TestSigninTwice(t *testing.T) {
	s, c := server(&Opts{Port: 8081, DBPath: testDBPath, Url: testUrl + "/send/email/{email}/{token}"})
	resp := doSignin("tom@test.ch", "testtest")
	resp.Body.Close()
	resp = doSignin("tom@test.ch", "testtest")

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	bodyString := string(bodyBytes)

	assert.Equal(t, 400, resp.StatusCode)
	assert.Equal(t, 0, strings.Index(bodyString, "SI05"))

	s.Shutdown(context.Background())
	<-c
}

func TestSigninWrong(t *testing.T) {
	s, c := server(&Opts{Port: 8081, DBPath: testDBPath, Url: testUrl + "/send/email/{email}/{token}"})
	resp := doSignin("tom@test.ch", "testtest")
	resp.Body.Close()
	resp = doSignin("tom@test.ch", "testtest")

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	bodyString := string(bodyBytes)

	assert.Equal(t, 400, resp.StatusCode)
	assert.Equal(t, 0, strings.Index(bodyString, "SI05"))

	s.Shutdown(context.Background())
	<-c
}

func TestConfirm(t *testing.T) {
	s, c := server(&Opts{Port: 8081, DBPath: testDBPath, Url: testUrl + "/send/email/{email}/{token}"})
	resp := doSignin("tom@test.ch", "testtest")
	assert.Equal(t, 200, resp.StatusCode)

	token := token("tom@test.ch")
	resp = doConfirm("tom@test.ch", token)
	assert.Equal(t, 200, resp.StatusCode)

	s.Shutdown(context.Background())
	<-c
}

func TestLogin(t *testing.T) {
	s, c := server(&Opts{Port: 8081, DBPath: testDBPath, Url: testUrl + "/send/email/{email}/{token}"})
	resp := doSignin("tom@test.ch", "testtest")
	assert.Equal(t, 200, resp.StatusCode)

	token := token("tom@test.ch")
	resp = doConfirm("tom@test.ch", token)
	assert.Equal(t, 200, resp.StatusCode)

	resp = doLogin("tom@test.ch", "testtest")
	assert.Equal(t, 200, resp.StatusCode)

	s.Shutdown(context.Background())
	<-c
}

func TestLoginFalse(t *testing.T) {
	s, c := server(&Opts{Port: 8081, DBPath: testDBPath, Url: testUrl + "/send/email/{email}/{token}", Dev: true})
	resp := doAll("tom@test.ch", "testtest")
	assert.Equal(t, 200, resp.StatusCode)

	resp = doLogin("tom@test.ch", "testtest")
	assert.Equal(t, 200, resp.StatusCode)

	resp = doLogin("tom@test.ch", "testtest2")
	assert.Equal(t, 401, resp.StatusCode)
	resp = doLogin("tom@test.ch2", "testtest")
	assert.Equal(t, 401, resp.StatusCode)

	s.Shutdown(context.Background())
	<-c
}

func TestRefresh(t *testing.T) {
	s, c := server(&Opts{Port: 8081, DBPath: testDBPath, Url: testUrl + "/send/email/{email}/{token}", Dev: true, Refresh: 1})
	resp := doAll("tom@test.ch", "testtest")
	assert.Equal(t, 200, resp.StatusCode)

	cookie := resp.Cookies()[0]
	token := resp.Header.Get("Token")
	resp = doRefresh(cookie.Value, token)
	assert.Equal(t, 200, resp.StatusCode)

	fmt.Printf("%s token, %v cookie", token, cookie.Value)
	s.Shutdown(context.Background())
	<-c
}

func doAll(email string, pass string) *http.Response {
	resp := doSignin(email, pass)
	token := token(email)
	resp = doConfirm(email, token)
	resp = doLogin(email, pass)
	return resp
}

func doRefresh(cookie string, token string) *http.Response {
	req, _ := http.NewRequest("GET", testUrl+"/refresh", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer: "+token)
	c := http.Cookie{Name: "refresh", Value: cookie, Path: "/refresh", Secure: false, HttpOnly: true}
	req.AddCookie(&c)
	resp, _ := http.DefaultClient.Do(req)
	return resp
}

func doLogin(email string, pass string) *http.Response {
	data := Credentials{
		Email:    email,
		Password: pass,
	}
	payloadBytes, _ := json.Marshal(data)
	body := bytes.NewReader(payloadBytes)
	req, _ := http.NewRequest("POST", testUrl+"/login", body)
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	return resp
}

func doSignin(email string, pass string) *http.Response {
	data := Credentials{
		Email:    email,
		Password: pass,
	}
	payloadBytes, _ := json.Marshal(data)
	body := bytes.NewReader(payloadBytes)

	req, _ := http.NewRequest("POST", testUrl+"/signin", body)
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	return resp
}

func doConfirm(email string, token string) *http.Response {
	c := &http.Client{
		Timeout: 15 * time.Second,
	}
	resp, _ := c.Get(testUrl + "/confirm/email/" + email + "/" + token)
	return resp
}

func token(email string) string {
	r, _ := getEmailToken(email)
	return string(r)
}

func getEmailToken(email string) (string, error) {
	var emailToken string
	err := db.QueryRow("SELECT emailToken from users where email = ?", email).Scan(&emailToken)
	if err != nil {
		return "", err
	}
	return emailToken, nil
}
