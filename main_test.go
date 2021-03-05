package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"github.com/stretchr/testify/assert"
	"github.com/xlzd/gotp"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	testDBPath    = "/tmp/fa.db"
	testDBDriver  = "sqlite3"
	testDBScripts = "rmdb.sql:init.sql"
	testDomain    = "localhost"
	testPort      = 8082
	testUrl       = "http://" + testDomain + ":8082"
)

var (
	testParams = []string{"-issuer=FFFS",
		"-port=" + strconv.Itoa(testPort),
		"-db-path=" + testDBPath,
		"-db-driver=" + testDBDriver,
		"-db-scripts=" + testDBScripts,
		"-email-url=" + testUrl + "/send/email/{email}/{token}",
		"-dev=true"}
)

/*
curl -v "http://localhost:8080/signup"   -X POST   -d "{\"email\":\"tom\",\"password\":\"test\"}"   -H "Content-Type: application/json"
*/
func TestSignup(t *testing.T) {
	shutdown := mainTest(testParams...)
	resp := doSignup("tom@test.ch", "testtest")

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	resp.Body.Close()
	shutdown()
}

func TestSignupWrongEmail(t *testing.T) {
	shutdown := mainTest(testParams...)
	resp := doSignup("tomtest.ch", "testtest")

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	bodyString := string(bodyBytes)
	assert.True(t, strings.Index(bodyString, "ERR-signup-02") > 0)

	resp.Body.Close()
	shutdown()
}

func TestSignupTwice(t *testing.T) {
	shutdown := mainTest(testParams...)
	resp := doSignup("tom@test.ch", "testtest")
	resp.Body.Close()
	resp = doSignup("tom@test.ch", "testtest")

	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	bodyString := string(bodyBytes)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.True(t, strings.Index(bodyString, "ERR-signup-07") > 0)

	resp.Body.Close()
	shutdown()
}

func TestSignupWrong(t *testing.T) {
	shutdown := mainTest(testParams...)
	resp := doSignup("tom@test.ch", "testtest")
	resp = doSignup("tom@test.ch", "testtest")

	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	bodyString := string(bodyBytes)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	log.Println(bodyString)
	assert.True(t, strings.Index(bodyString, "ERR-signup-07") > 0)

	resp.Body.Close()
	shutdown()
}

func TestConfirm(t *testing.T) {
	shutdown := mainTest(testParams...)
	resp := doSignup("tom@test.ch", "testtest")
	assert.Equal(t, 200, resp.StatusCode)

	token := token("tom@test.ch")
	resp = doConfirm("tom@test.ch", token)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	resp.Body.Close()
	shutdown()
}

func TestLogin(t *testing.T) {
	shutdown := mainTest(testParams...)
	resp := doSignup("tom@test.ch", "testtest")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	token := token("tom@test.ch")
	resp = doConfirm("tom@test.ch", token)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	resp = doLogin("tom@test.ch", "testtest", "", "")
	assert.Equal(t, http.StatusSeeOther, resp.StatusCode)

	resp.Body.Close()
	shutdown()
}

func TestLoginFalse(t *testing.T) {
	shutdown := mainTest(testParams...)
	resp := doAll("tom@test.ch", "testtest", "0123456789012345678901234567890123456789012")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	resp = doLogin("tom@test.ch", "testtest", "", "0123456789012345678901234567890123456789012")
	assert.Equal(t, http.StatusSeeOther, resp.StatusCode)

	resp = doLogin("tom@test.ch", "testtest2", "", "0123456789012345678901234567890123456789012")
	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.True(t, strings.Index(string(bodyBytes), "ERR-checkEmail-06, user tom@test.ch password mismatch") > 0)

	resp = doLogin("tom@test.ch2", "testtest", "", "0123456789012345678901234567890123456789012")
	bodyBytes, _ = ioutil.ReadAll(resp.Body)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.True(t, strings.Index(string(bodyBytes), "ERR-checkEmail-01, DB select, tom@test.ch2 err sql: no rows in result set") > 0)

	resp.Body.Close()
	shutdown()
}

func TestRefresh(t *testing.T) {
	tmp := append(testParams, "-expire-refresh=10")
	shutdown := mainTest(tmp...)
	resp := doAll("tom@test.ch", "testtest", "0123456789012345678901234567890123456789012")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	oauth := OAuth{}
	json.NewDecoder(resp.Body).Decode(&oauth)
	assert.NotEqual(t, "", oauth.AccessToken)
	shutdown()
}

func TestReset(t *testing.T) {
	tmp := append(testParams, "-expire-refresh=1")
	shutdown := mainTest(tmp...)

	resp := doAll("tom@test.ch", "testtest", "0123456789012345678901234567890123456789012")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	resp = doReset("tom@test.ch")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	token, _ := getForgotEmailToken("tom@test.ch")

	resp = doConfirmReset("tom@test.ch", token, "testtest2")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	resp = doLogin("tom@test.ch", "testtest2", "", "0123456789012345678901234567890123456789012")
	assert.Equal(t, http.StatusSeeOther, resp.StatusCode)

	resp.Body.Close()
	shutdown()
}

func TestResetFailed(t *testing.T) {
	tmp := append(testParams, "-expire-refresh=1")
	shutdown := mainTest(tmp...)
	resp := doAll("tom@test.ch", "testtest", "0123456789012345678901234567890123456789012")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	resp = doReset("tom@test.ch")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	token, _ := getForgotEmailToken("tom@test.ch")

	resp = doConfirmReset("tom@test.ch", token, "testtest2")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	resp = doLogin("tom@test.ch", "testtest", "", "0123456789012345678901234567890123456789012")
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	resp.Body.Close()
	shutdown()
}

func TestTOTP(t *testing.T) {
	shutdown := mainTest(testParams...)
	resp := doAll("tom@test.ch", "testtest", "0123456789012345678901234567890123456789012")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	oauth := OAuth{}
	json.NewDecoder(resp.Body).Decode(&oauth)

	resp = doTOTP(oauth.AccessToken)
	p := ProvisioningUri{}
	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	json.Unmarshal(bodyBytes, &p)
	secret := strings.SplitN(p.Uri, "=", 2)
	secret = strings.SplitN(secret[1], "&", 2)
	totp := newTOTP(secret[0])
	conf := totp.Now()

	resp = doTOTPConfirm(conf, oauth.AccessToken)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	resp.Body.Close()
	shutdown()
}

func TestLoginTOTP(t *testing.T) {
	shutdown := mainTest(testParams...)
	resp := doAll("tom@test.ch", "testtest", "0123456789012345678901234567890123456789012")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	oauth := OAuth{}
	json.NewDecoder(resp.Body).Decode(&oauth)

	totp := doAllTOTP(oauth.AccessToken)

	resp = doLogin("tom@test.ch", "testtest", totp.Now(), "0123456789012345678901234567890123456789012")
	assert.Equal(t, http.StatusSeeOther, resp.StatusCode)

	resp = doLogin("tom@test.ch", "testtest", "", "0123456789012345678901234567890123456789012")
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
		Email:      email,
		Password:   password,
		EmailToken: token,
	}
	payloadBytes, _ := json.Marshal(data)
	body := bytes.NewReader(payloadBytes)
	req, _ := http.NewRequest("POST", testUrl+"/confirm/reset", body)
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	return resp
}

func doReset(email string) *http.Response {
	req, _ := http.NewRequest("POST", testUrl+"/reset/"+email, nil)
	resp, _ := http.DefaultClient.Do(req)
	return resp
}

func doAll(email string, pass string, secret string) *http.Response {
	resp := doSignup(email, pass)
	token := token(email)
	resp = doConfirm(email, token)
	resp = doLogin(email, pass, "", secret)
	code := resp.Header.Get("Location")[6:]
	resp = doCode(code, secret)
	return resp
}

func doCode(codeToken string, codeVerifier string) *http.Response {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", codeToken)
	data.Set("code_verifier", codeVerifier)
	req, _ := http.NewRequest("POST", testUrl+"/oauth/token", strings.NewReader(data.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, _ := http.DefaultClient.Do(req)
	return resp
}

func doRefresh(refreshToken string) *http.Response {
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	req, _ := http.NewRequest("POST", testUrl+"/oauth/token", strings.NewReader(data.Encode()))
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, _ := http.DefaultClient.Do(req)
	return resp
}

func doLogin(email string, pass string, totp string, secret string) *http.Response {
	h := sha256.Sum256([]byte(secret))
	data := Credentials{
		Email:                   email,
		Password:                pass,
		TOTP:                    totp,
		CodeChallenge:           base64.RawURLEncoding.EncodeToString(h[:]),
		CodeCodeChallengeMethod: "S256",
	}

	//do not follow redirects: https://stackoverflow.com/questions/23297520/how-can-i-make-the-go-http-client-not-follow-redirects-automatically
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	payloadBytes, _ := json.Marshal(data)
	body := bytes.NewReader(payloadBytes)
	req, _ := http.NewRequest(http.MethodPost, testUrl+"/login", body)
	req.Header.Set("Content-Type", "application/json")
	resp, _ := client.Do(req)
	return resp
}

func doSignup(email string, pass string) *http.Response {
	data := Credentials{
		Email:    email,
		Password: pass,
	}
	payloadBytes, _ := json.Marshal(data)
	body := bytes.NewReader(payloadBytes)

	req, err := http.NewRequest("POST", testUrl+"/signup", body)
	if err != nil {
		log.Printf("request failed %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("request failed %v", err)
	}
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

func TestSecret(t *testing.T) {
	h := sha256.Sum256([]byte("test"))
	s := base64.RawURLEncoding.EncodeToString(h[:])
	assert.Equal(t, "n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg", s)
}

func TestGetAttrDN(t *testing.T) {

	assert.Equal(t,
		getAttrDN("CN=tom,OU=P_Internal,OU=P_Users,DC=test,DC=ch", "cn"),
		"tom")

	assert.Equal(t,
		getAttrDN("CN=tom,OU=P_Internal,OU=P_Users,DC=test,DC=ch", "cn"),
		getAttrDN("cn=tom,ou=P_Internal,ou=P_Users,dc=test,dc=ch", "CN"))
}

func mainTest(args ...string) func() {
	oldArgs := os.Args
	os.Args = []string{oldArgs[0]}
	os.Args = append(os.Args, args...)

	opts = NewOpts()
	var err error
	db, err = initDB()
	if err != nil {
		log.Fatal(err)
	}
	setupDB()
	serverRest, doneChannelRest, err := serverRest()
	if err != nil {
		log.Fatal(err)
	}
	serverLdap, doneChannelLdap := serverLdap()

	return func() {
		os.Args = oldArgs
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
		serverRest.Shutdown(context.Background())
		serverLdap.Stop()
		if serverLdap.Listener != nil {
			serverLdap.Listener.Close()
		}
		<-doneChannelRest
		<-doneChannelLdap
		err := db.Close()
		if err != nil {
			log.Printf("could not close DB %v", err)
		}
		//for testing, the DB needs to be wiped after each run
		err = os.Remove(opts.DBPath)
		if err != nil {
			log.Printf("could not remove DB file %v", err)
		}
	}
}
