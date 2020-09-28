package main

import (
	"bytes"
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"github.com/xlzd/gotp"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"
)

const (
	testDBPath = "/tmp/fa.db"
	testDomain = "localhost"
	testUrl    = "http://" + testDomain + ":8081"
)

/*
curl -v "http://localhost:8080/signup"   -X POST   -d "{\"email\":\"tom\",\"password\":\"test\"}"   -H "Content-Type: application/json"
*/
func TestSignup(t *testing.T) {
	shutdown := mainTest(&Opts{Port: 8081, DBPath: testDBPath, UrlEmail: testUrl + "/send/email/{action}/{email}/{token}", Dev: "true"})
	resp := doSignup("tom@test.ch", "testtest")

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	resp.Body.Close()
	shutdown()
}

func TestSignupWrongEmail(t *testing.T) {
	shutdown := mainTest(&Opts{Port: 8081, DBPath: testDBPath, UrlEmail: testUrl + "/send/email/{action}/{email}/{token}", Dev: "true"})
	resp := doSignup("tomtest.ch", "testtest")

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	bodyString := string(bodyBytes)
	assert.True(t, strings.Index(bodyString, "ERR-signup-02") > 0)

	resp.Body.Close()
	shutdown()
}

func TestSignupTwice(t *testing.T) {
	shutdown := mainTest(&Opts{Port: 8081, DBPath: testDBPath, UrlEmail: testUrl + "/send/email/{action}/{email}/{token}", Dev: "true"})
	resp := doSignup("tom@test.ch", "testtest")
	resp.Body.Close()
	resp = doSignup("tom@test.ch", "testtest")

	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	bodyString := string(bodyBytes)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.True(t, strings.Index(bodyString, "ERR-signup-06") > 0)

	resp.Body.Close()
	shutdown()
}

func TestSignupWrong(t *testing.T) {
	shutdown := mainTest(&Opts{Port: 8081, DBPath: testDBPath, UrlEmail: testUrl + "/send/email/{action}/{email}/{token}", Dev: "true"})
	resp := doSignup("tom@test.ch", "testtest")
	resp = doSignup("tom@test.ch", "testtest")

	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	bodyString := string(bodyBytes)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	log.Println(bodyString)
	assert.True(t, strings.Index(bodyString, "ERR-signup-06") > 0)

	resp.Body.Close()
	shutdown()
}

func TestConfirm(t *testing.T) {
	shutdown := mainTest(&Opts{Port: 8081, DBPath: testDBPath, UrlEmail: testUrl + "/send/email/{action}/{email}/{token}", Dev: "true"})
	resp := doSignup("tom@test.ch", "testtest")
	assert.Equal(t, 200, resp.StatusCode)

	token := token("tom@test.ch")
	resp = doConfirm("tom@test.ch", token)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	resp.Body.Close()
	shutdown()
}

func TestLogin(t *testing.T) {
	shutdown := mainTest(&Opts{Port: 8081, DBPath: testDBPath, UrlEmail: testUrl + "/send/email/{action}/{email}/{token}", Dev: "true"})
	resp := doSignup("tom@test.ch", "testtest")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	token := token("tom@test.ch")
	resp = doConfirm("tom@test.ch", token)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	resp = doLogin("tom@test.ch", "testtest", "")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	resp.Body.Close()
	shutdown()
}

func TestLoginFalse(t *testing.T) {
	shutdown := mainTest(&Opts{Port: 8081, DBPath: testDBPath, UrlEmail: testUrl + "/send/email/{action}/{email}/{token}", Dev: "true"})
	resp := doAll("tom@test.ch", "testtest")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	resp = doLogin("tom@test.ch", "testtest", "")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	resp = doLogin("tom@test.ch", "testtest2", "")
	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.True(t, strings.Index(string(bodyBytes), "ERR-checkEmail-06, user tom@test.ch password mismatch") > 0)

	resp = doLogin("tom@test.ch2", "testtest", "")
	bodyBytes, _ = ioutil.ReadAll(resp.Body)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.True(t, strings.Index(string(bodyBytes), "ERR-checkEmail-01, DB select, tom@test.ch2 err sql: no rows in result set") > 0)

	resp.Body.Close()
	shutdown()
}

func TestRefresh(t *testing.T) {
	shutdown := mainTest(&Opts{Port: 8081, DBPath: testDBPath, UrlEmail: testUrl + "/send/email/{action}/{email}/{token}", Dev: "true", ExpireRefresh: 10})
	resp := doAll("tom@test.ch", "testtest")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	token1 := resp.Header.Get("Token")

	time.Sleep(time.Second)
	cookie := resp.Cookies()[0]
	resp = doRefresh(cookie.Value)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	token2 := resp.Header.Get("Token")
	assert.NotEqual(t, token1, token2)

	resp.Body.Close()
	shutdown()
}

func TestReset(t *testing.T) {
	shutdown := mainTest(&Opts{Port: 8081, DBPath: testDBPath, UrlEmail: testUrl + "/send/email/{action}/{email}/{token}", Dev: "true", ExpireRefresh: 1})

	resp := doAll("tom@test.ch", "testtest")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	resp = doReset("tom@test.ch")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	token, _ := getForgotEmailToken("tom@test.ch")

	resp = doConfirmReset("tom@test.ch", token, "testtest2")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	resp = doLogin("tom@test.ch", "testtest2", "")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	resp.Body.Close()
	shutdown()
}

func TestResetFailed(t *testing.T) {
	shutdown := mainTest(&Opts{Port: 8081, DBPath: testDBPath, UrlEmail: testUrl + "/send/email/{action}/{email}/{token}", Dev: "true", ExpireRefresh: 1})

	resp := doAll("tom@test.ch", "testtest")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	resp = doReset("tom@test.ch")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	token, _ := getForgotEmailToken("tom@test.ch")

	resp = doConfirmReset("tom@test.ch", token, "testtest2")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	resp = doLogin("tom@test.ch", "testtest", "")
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	resp.Body.Close()
	shutdown()
}

func TestTOTP(t *testing.T) {
	shutdown := mainTest(&Opts{Issuer: "FFFS", Port: 8081, DBPath: testDBPath, UrlEmail: testUrl + "/send/email/{action}/{email}/{token}", Dev: "true"})
	resp := doAll("tom@test.ch", "testtest")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	token := resp.Header.Get("Token")

	resp = doTOTP(token)
	p := ProvisioningUri{}
	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	json.Unmarshal(bodyBytes, &p)
	secret := strings.SplitN(p.Uri, "=", 2)
	secret = strings.SplitN(secret[1], "&", 2)
	totp := newTOTP(secret[0])
	conf := totp.Now()

	resp = doTOTPConfirm(conf, token)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	resp.Body.Close()
	shutdown()
}

func TestLoginTOTP(t *testing.T) {
	shutdown := mainTest(&Opts{Issuer: "FFFS", Port: 8081, DBPath: testDBPath, UrlEmail: testUrl + "/send/email/{action}/{email}/{token}", Dev: "true"})
	resp := doAll("tom@test.ch", "testtest")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	token := resp.Header.Get("Token")

	totp := doAllTOTP(token)

	resp = doLogin("tom@test.ch", "testtest", totp.Now())
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	resp = doLogin("tom@test.ch", "testtest", "")
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	resp.Body.Close()
	shutdown()
}

func doTOTP(token string) *http.Response {
	req, _ := http.NewRequest("POST", testUrl+"/setup/totp", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ := http.DefaultClient.Do(req)
	return resp
}

func doTOTPConfirm(conf string, token string) *http.Response {
	req, _ := http.NewRequest("POST", testUrl+"/confirm/totp/"+conf, nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ := http.DefaultClient.Do(req)
	return resp
}

func doAllTOTP(token string) *gotp.TOTP {
	resp := doTOTP(token)
	p := ProvisioningUri{}
	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	json.Unmarshal(bodyBytes, &p)
	secret := strings.SplitN(p.Uri, "=", 2)
	secret = strings.SplitN(secret[1], "&", 2)
	totp := newTOTP(secret[0])
	conf := totp.Now()
	resp = doTOTPConfirm(conf, token)
	return totp
}

func doConfirmReset(email string, token string, password string) *http.Response {
	data := Credentials{
		Password: password,
	}
	payloadBytes, _ := json.Marshal(data)
	body := bytes.NewReader(payloadBytes)
	req, _ := http.NewRequest("POST", testUrl+"/confirm/reset/"+email+"/"+token, body)
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	return resp
}

func doReset(email string) *http.Response {
	req, _ := http.NewRequest("POST", testUrl+"/reset/"+email, nil)
	resp, _ := http.DefaultClient.Do(req)
	return resp
}

func doAll(email string, pass string) *http.Response {
	resp := doSignup(email, pass)
	token := token(email)
	resp = doConfirm(email, token)
	resp = doLogin(email, pass, "")
	return resp
}

func doRefresh(cookie string) *http.Response {
	req, _ := http.NewRequest("POST", testUrl+"/refresh", nil)
	req.Header.Set("Content-Type", "application/json")
	c := http.Cookie{Name: "refresh", Value: cookie, Path: "/refresh", Secure: false, HttpOnly: true}
	req.AddCookie(&c)
	resp, _ := http.DefaultClient.Do(req)
	return resp
}

func doLogin(email string, pass string, totp string) *http.Response {
	data := Credentials{
		Email:    email,
		Password: pass,
		TOTP:     totp,
	}
	payloadBytes, _ := json.Marshal(data)
	body := bytes.NewReader(payloadBytes)
	req, _ := http.NewRequest("POST", testUrl+"/login", body)
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	return resp
}

func doSignup(email string, pass string) *http.Response {
	data := Credentials{
		Email:    email,
		Password: pass,
	}
	payloadBytes, _ := json.Marshal(data)
	body := bytes.NewReader(payloadBytes)

	req, _ := http.NewRequest("POST", testUrl+"/signup", body)
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	return resp
}

func doConfirm(email string, token string) *http.Response {
	c := &http.Client{
		Timeout: 15 * time.Second,
	}
	resp, _ := c.Get(testUrl + "/confirm/signup/" + email + "/" + token)
	return resp
}

func token(email string) string {
	r, _ := getEmailToken(email)
	return string(r)
}

func getEmailToken(email string) (string, error) {
	var emailToken string
	err := db.QueryRow("SELECT emailToken from auth where email = ?", email).Scan(&emailToken)
	if err != nil {
		return "", err
	}
	return emailToken, nil
}

func getForgotEmailToken(email string) (string, error) {
	var forgetEmailToken string
	err := db.QueryRow("SELECT forgetEmailToken from auth where email = ?", email).Scan(&forgetEmailToken)
	if err != nil {
		return "", err
	}
	return forgetEmailToken, nil
}
