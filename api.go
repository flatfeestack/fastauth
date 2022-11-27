package main

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/go-jose/go-jose/v3"
	"github.com/gorilla/mux"
	"github.com/gorilla/schema"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/text/language"
	"html/template"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type Timewarp struct {
	Offset int `json:"offset"`
}

type EmailRequest struct {
	MailTo      string `json:"mail_to,omitempty"`
	Subject     string `json:"subject"`
	TextMessage string `json:"text_message"`
	HtmlMessage string `json:"html_message"`
}

type EmailToken struct {
	Email      string `json:"email"`
	EmailToken string `json:"emailToken"`
}

type scryptParam struct {
	n   int
	r   int
	p   int
	len int
}

const (
	flowPassword   = "pwd"
	flowCode       = "code"
	flowInvitation = "inv"
)

var (
	m       = map[uint8]scryptParam{0: {16384, 8, 1, 32}}
	matcher = language.NewMatcher([]language.Tag{
		language.English,
		language.German,
	})
)

func confirmEmail(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	token := vars["token"]
	email := vars["email"]

	err := updateEmailToken(email, token)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-confirm-email-01, update email token for %v failed, token %v: %v", email, token, err)
		return
	}

	result, err := findAuthByEmail(email)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-writeOAuth, findAuthByEmail for %v failed, %v", email, err)
		return
	}

	if result.flowType == flowCode {
		keys := r.URL.Query()
		uri := keys.Get("redirect_uri")
		w.Header().Set("Location", uri+"&email="+url.QueryEscape(email))
		w.WriteHeader(http.StatusSeeOther)
	} else {
		writeOAuth(w, result)
	}
}

func writeOAuth(w http.ResponseWriter, result *dbRes) {
	encodedAccessToken, encodedRefreshToken, expiresAt, err := encodeTokens(result)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_grant", "blocked", "cannot encode tokens %v", err)
		return
	}

	oauth := OAuth{
		AccessToken:  encodedAccessToken,
		TokenType:    "Bearer",
		RefreshToken: encodedRefreshToken,
		Expires:      strconv.FormatInt(expiresAt, 10),
	}
	oauthEnc, err := json.Marshal(oauth)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_grant", "blocked", "ERR-oauth-08, cannot verify refresh token %v", err)
		return
	}
	w.Write(oauthEnc)
}

func confirmEmailPost(w http.ResponseWriter, r *http.Request) {
	var et EmailToken
	err := json.NewDecoder(r.Body).Decode(&et)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-signup-01, cannot parse JSON credentials %v", err)
		return
	}

	err = updateEmailToken(et.Email, et.EmailToken)
	if err != nil {
		//the token can be only updated once. Otherwise, anyone with the link can always login. Thus, if the email
		//leaks, the account is compromised. Thus, disallow this.
		writeErr(w, http.StatusForbidden, "invalid_request", "blocked", "ERR-confirm-email-01, update email token for %v failed, token %v: %v", et.Email, et.EmailToken, err)
		return
	}

	result, err := findAuthByEmail(et.Email)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-writeOAuth, findAuthByEmail for %v failed, %v", et.Email, err)
		return
	}

	writeOAuth(w, result)
}

func invite(w http.ResponseWriter, r *http.Request, claims *TokenClaims) {
	vars := mux.Vars(r)
	email := vars["email"]

	params := map[string]interface{}{}
	if r.Body != nil && r.Body != http.NoBody {
		err := json.NewDecoder(r.Body).Decode(&params)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "cannot decode invite %v", err)
			return
		}
	}
	params["lang"] = lang(r)

	err := validateEmail(email)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "email in invite is wrong %v", err)
		return
	}

	u, err := findAuthByEmail(email)

	if err != nil && err != sql.ErrNoRows {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "find email %v", err)
		return
	}

	if u != nil {
		//user already exists, send email to direct him to the invitations
		params["url"] = opts.EmailLinkPrefix + "/user/invitations"
		e := prepareEmail(email, params,
			"template-subject-invite-old_"+claims.Scope, "You have been invited by "+claims.Subject,
			"template-plain-invite-old_"+claims.Scope, "Click on this link to see your invitation: "+params["url"].(string),
			"template-html-invite-old_"+claims.Scope, params["lang"].(string))
		go func() {
			err = sendEmail(opts.EmailUrl, e)
			if err != nil {
				log.Printf("ERR-signup-07, send email failed: %v, %v\n", opts.EmailUrl, err)
			}
		}()

		return
	}

	emailToken, err := genToken()
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "cannot generate rnd token for %v, err %v", email, err)
		return
	}

	refreshToken, err := genToken()
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "cannot generate rnd refresh token for %v, err %v", email, err)
		return
	}

	params["token"] = emailToken
	params["email"] = email

	//TODO: better check if user is already in DB
	err = insertUser(email, nil, emailToken, refreshToken, flowInvitation, timeNow())
	if err != nil {
		log.Printf("could not insert user %v", err)
		params["url"] = opts.EmailLinkPrefix + "/login"

		e := prepareEmail(email, params,
			"template-subject-login_"+claims.Scope, "You have been invited again by "+claims.Subject,
			"template-plain-login_"+claims.Scope, "Click on this link to login: "+params["url"].(string),
			"template-html-login_"+claims.Scope, params["lang"].(string))

		go func() {
			err = sendEmail(opts.EmailUrl, e)
			if err != nil {
				log.Printf("ERR-signup-07, send email failed: %v, %v\n", opts.EmailUrl, err)
			}
		}()

		//do not write error, we do not want the user to know that this user does not exist (privacy)
		w.WriteHeader(http.StatusOK)
		return
	} else {
		params["url"] = opts.EmailLinkPrefix + "/confirm/invite/" + url.QueryEscape(email) + "/" + emailToken + "/" + claims.Subject

		e := prepareEmail(email, params,
			"template-subject-invite-new_"+claims.Scope, "You have been invited by "+claims.Subject,
			"template-plain-invite-new_"+claims.Scope, "Click on this link to create your account: "+params["url"].(string),
			"template-html-invite-new_"+claims.Scope, params["lang"].(string))

		go func() {
			err = sendEmail(opts.EmailUrl, e)
			if err != nil {
				log.Printf("ERR-signup-07, send email failed: %v, %v\n", opts.EmailUrl, err)
			}
		}()

		if opts.Env == "dev" || opts.Env == "local" {
			w.Write([]byte(`{"url":"` + params["url"].(string) + `"}`))
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}
}

func confirmInvite(w http.ResponseWriter, r *http.Request) {
	var cred Credentials
	err := json.NewDecoder(r.Body).Decode(&cred)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-signup-01, cannot parse JSON credentials %v", err)
		return
	}

	newPw, err := newPw(cred.Password, 0)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-signup-05, key %v error: %v", cred.Email, err)
		return
	}
	err = updatePasswordInvite(cred.Email, cred.EmailToken, newPw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-confirm-reset-email-07, update user failed: %v", err)
		return
	}

	result, err := findAuthByEmail(cred.Email)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-writeOAuth, findAuthByEmail for %v failed, %v", cred.Email, err)
		return
	}

	writeOAuth(w, result)
}

func signup(w http.ResponseWriter, r *http.Request) {
	var cred Credentials
	err := json.NewDecoder(r.Body).Decode(&cred)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-signup-01, cannot parse JSON credentials %v", err)
		return
	}

	err = validateEmail(cred.Email)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-signup-02, email is wrong %v", err)
		return
	}

	err = validatePassword(cred.Password)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-signup-03, password is wrong %v", err)
		return
	}

	emailToken, err := genToken()
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-signup-04, RND %v err %v", cred.Email, err)
		return
	}

	//https://security.stackexchange.com/questions/11221/how-big-should-salt-be
	calcPw, err := newPw(cred.Password, 0)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-signup-05, key %v error: %v", cred.Email, err)
		return
	}

	refreshToken, err := genToken()
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-signup-06, key %v error: %v", cred.Email, err)
		return
	}

	flowType := flowPassword
	urlParams := ""
	if cred.RedirectUri != "" {
		urlParams = "?redirect_uri=" + url.QueryEscape(cred.RedirectUri)
		i := strings.Index(cred.RedirectUri, "?")
		if i < len(cred.RedirectUri) && i > 0 {
			m, err := url.ParseQuery(cred.RedirectUri[strings.Index(cred.RedirectUri, "?")+1:])
			if err != nil {
				writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-signup-07, insert user failed: %v", err)
				return
			}
			if m.Get("code_challenge") != "" {
				flowType = flowCode
			}
		}
	}

	//check if user exists than was not activated yet. In that case, resend the email and don't try to insert
	//the user, as this would fail due to constraints

	err = insertUser(cred.Email, calcPw, emailToken, refreshToken, flowType, timeNow())
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-signup-07, insert user failed: %v", err)
		return
	}

	params := map[string]interface{}{}
	params["token"] = emailToken
	params["email"] = cred.Email
	params["url"] = opts.EmailLinkPrefix + "/confirm/signup/" + url.QueryEscape(cred.Email) + "/" + emailToken + urlParams
	params["lang"] = lang(r)

	e := prepareEmail(cred.Email, params,
		"template-subject-signup_", "Validate your email",
		"template-plain-signup_", "Click on this link: "+params["url"].(string),
		"template-html-signup_", params["lang"].(string))

	go func() {
		err = sendEmail(opts.EmailUrl, e)
		if err != nil {
			log.Printf("ERR-signup-07, send email failed: %v, %v\n", opts.EmailUrl, err)
		}
	}()

	if opts.Env == "dev" || opts.Env == "local" {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"url":"` + params["url"].(string) + `"}`))
	} else {
		w.WriteHeader(http.StatusOK)
	}
}

func lang(r *http.Request) string {
	accept := r.Header.Get("Accept-Language")
	tag, _ := language.MatchStrings(matcher, accept)
	b, _ := tag.Base()
	return b.String()
}

func parseTemplate(filename string, other map[string]interface{}) string {
	textMessage := ""
	tmplPlain, err := template.ParseFiles(filename)
	if err == nil {
		var buf bytes.Buffer
		err = tmplPlain.Execute(&buf, other)
		if err == nil {
			textMessage = buf.String()
		} else {
			log.Printf("cannot execute template file [%v], err: %v", filename, err)
		}
	} else {
		log.Printf("cannot prepare file template file [%v], err: %v", filename, err)
	}
	return textMessage
}

func login(w http.ResponseWriter, r *http.Request) {
	var cred Credentials

	//https://medium.com/@xoen/golang-read-from-an-io-readwriter-without-loosing-its-content-2c6911805361
	var bodyCopy []byte
	var err error
	if r.Body != nil {
		bodyCopy, err = ioutil.ReadAll(r.Body)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-login-01, cannot parse POST data %v", err)
			return
		}
	}

	r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyCopy))
	err = json.NewDecoder(r.Body).Decode(&cred)
	if err != nil {
		r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyCopy))
		err = r.ParseForm()
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-login-01, cannot parse POST data %v", err)
			return
		}
		err = schema.NewDecoder().Decode(&cred, r.PostForm)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-login-02, cannot populate POST data %v", err)
			return
		}
	}

	result, errString, err := checkEmailPassword(cred.Email, cred.Password)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_client", errString, "ERR-login-02 %v", err)
		return
	}

	//SMS logic
	if result.totp != nil && result.sms != nil && result.smsVerified != nil {
		totp := newTOTP(*result.totp)
		token := totp.Now()
		if cred.TOTP == "" {
			url := strings.Replace(opts.UrlSms, "{sms}", *result.sms, 1)
			url = strings.Replace(url, "{token}", token, 1)
			err = sendSMS(url)
			if err != nil {
				writeErr(w, http.StatusUnauthorized, "invalid_request", "blocked", "ERR-login-07, send sms failed %v error: %v", cred.Email, err)
				return
			}
			writeErr(w, http.StatusLocked, "invalid_client", "blocked", "ERR-login-08, waiting for sms verification: %v", cred.Email)
			return
		} else if token != cred.TOTP {
			writeErr(w, http.StatusForbidden, "invalid_request", "blocked", "ERR-login-09, sms wrong token, %v err %v", cred.Email, err)
			return
		}
	}

	//TOTP logic
	if result.totp != nil && result.totpVerified != nil {
		totp := newTOTP(*result.totp)
		token := totp.Now()
		if token != cred.TOTP {
			writeErr(w, http.StatusForbidden, "invalid_request", "blocked", "ERR-login-10, totp wrong token, %v err %v", cred.Email, err)
			return
		}
	}

	if cred.CodeCodeChallengeMethod != "" {
		//return the code flow
		handleCode(w, cred.Email, cred.CodeChallenge, cred.CodeCodeChallengeMethod, cred.RedirectUri, cred.RedirectAs201)
	} else {
		refreshToken, err := resetRefreshToken(result.refreshToken)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_grant", "blocked", "ERR-login-15, cannot reset refresh token %v", err)
			return
		}
		encodedAccessToken, encodedRefreshToken, expiresAt, err := checkRefresh(cred.Email, refreshToken)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_grant", "blocked", "ERR-login-16, cannot verify refresh token %v", err)
			return
		}

		oauth := OAuth{AccessToken: encodedAccessToken, TokenType: "Bearer", RefreshToken: encodedRefreshToken, Expires: strconv.FormatInt(expiresAt, 10)}
		oauthEnc, err := json.Marshal(oauth)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_grant", "blocked", "ERR-login-17, cannot encode refresh token %v", err)
			return
		}
		w.Write(oauthEnc)
	}
}

func handleCode(w http.ResponseWriter, email string, codeChallenge string, codeChallengeMethod string, redirectUri string, redirectAs201 bool) {
	encoded, _, err := encodeCodeToken(email, codeChallenge, codeChallengeMethod)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "invalid_request", "blocked", "ERR-login-14, cannot set refresh token for %v, %v", email, err)
		return
	}
	w.Header().Set("Location", redirectUri+"?code="+encoded)
	if redirectAs201 {
		w.WriteHeader(http.StatusCreated)
	} else {
		w.WriteHeader(http.StatusSeeOther)
	}
}

func displayEmail(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	token := vars["token"]
	email, err := url.QueryUnescape(vars["email"])
	if err != nil {
		email = fmt.Sprintf("email decoding error %v", err)
		log.Printf(email)
	}
	action, err := url.QueryUnescape(vars["action"])
	if err != nil {
		action = fmt.Sprintf("action decoding error %v", err)
		log.Printf(action)
	}

	if action == "signup" {
		fmt.Printf("go to URL: http://%s/confirm/signup/%s/%s\n", r.Host, email, token)
	} else if action == "reset" {
		fmt.Printf("go to URL: http://%s/confirm/reset/%s/%s\n", r.Host, email, token)
	}

	w.WriteHeader(http.StatusOK)
}

func displaySMS(_ http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	token := vars["token"]
	sms, err := url.QueryUnescape(vars["sms"])
	if err != nil {
		log.Printf("decoding error %v", err)
	}
	fmt.Printf("Send token [%s] to NR %s\n", token, sms)
}

func resetEmail(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	email, err := url.QueryUnescape(vars["email"])
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-confirm-reset-email-01, query unescape email %v err: %v", vars["email"], err)
		return
	}

	forgetEmailToken, err := genToken()
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-reset-email-02, RND %v err %v", email, err)
		return
	}

	err = updateEmailForgotToken(email, forgetEmailToken)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-reset-email-03, update token for %v failed, token %v: %v", email, forgetEmailToken, err)
		return
	}

	params := map[string]interface{}{}
	err = json.NewDecoder(r.Body).Decode(&params)
	if err != nil {
		log.Printf("No or wrong json, ignoring [%v]", err)
	}

	params["email"] = email
	params["url"] = opts.EmailLinkPrefix + "/confirm/reset/" + email + "/" + forgetEmailToken
	params["lang"] = lang(r)

	e := prepareEmail(email, params,
		"template-subject-reset_", "Reset your email",
		"template-plain-reset_", "Click on this link: "+params["url"].(string),
		"template-html-reset_", params["lang"].(string))

	go func() {
		err = sendEmail(opts.EmailUrl, e)
		if err != nil {
			log.Printf("ERR-reset-email-04, send email failed: %v", opts.EmailUrl)
		}
	}()

	w.WriteHeader(http.StatusOK)
}

func newPw(password string, version uint8) ([]byte, error) {
	salt, err := genRnd(16) //salt is always 128bit
	if err != nil {
		return nil, err
	}

	calcPw, err := scrypt.Key([]byte(password), salt, m[version].n, m[version].r, m[version].p, m[version].len)
	if err != nil {
		return nil, err
	}

	ret := []byte{version}
	ret = append(ret, salt...)
	ret = append(ret, calcPw...)
	return ret, nil
}

func checkPw(checkPw string, encodedPw []byte) ([]byte, []byte, error) {
	key := encodedPw[0]
	salt := encodedPw[1:17] //salt is always 128bit
	storedPw := encodedPw[17 : 17+m[key].len]
	calcPw, err := scrypt.Key([]byte(checkPw), salt, m[key].n, m[key].r, m[key].p, m[key].len)
	return storedPw, calcPw, err
}

func confirmReset(w http.ResponseWriter, r *http.Request) {
	var cred Credentials
	err := json.NewDecoder(r.Body).Decode(&cred)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-signup-01, cannot parse JSON credentials %v", err)
		return
	}
	newPw, err := newPw(cred.Password, 0)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-signup-05, key %v error: %v", cred.Email, err)
		return
	}
	err = updatePasswordForgot(cred.Email, cred.EmailToken, newPw)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-confirm-reset-email-07, update user failed: %v", err)
		return
	}

	result, err := findAuthByEmail(cred.Email)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-writeOAuth, findAuthByEmail for %v failed, %v", cred.Email, err)
		return
	}

	writeOAuth(w, result)
}

func setupTOTP(w http.ResponseWriter, _ *http.Request, claims *TokenClaims) {
	secret, err := genToken()
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-setup-totp-01, RND %v err %v", claims.Subject, err)
		return
	}

	err = updateTOTP(claims.Subject, secret)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-setup-totp-02, update failed %v err %v", claims.Subject, err)
		return
	}

	totp := newTOTP(secret)
	p := ProvisioningUri{}
	p.Uri = totp.ProvisioningUri(claims.Subject, opts.Issuer)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(p)
}

func confirmTOTP(w http.ResponseWriter, r *http.Request, claims *TokenClaims) {
	vars := mux.Vars(r)
	token, err := url.QueryUnescape(vars["token"])
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-confirm-totp-01, query unescape token %v err: %v", vars["token"], err)
		return
	}

	result, err := findAuthByEmail(claims.Subject)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-confirm-totp-02, DB select, %v err %v", claims.Subject, err)
		return
	}

	totp := newTOTP(*result.totp)
	if token != totp.Now() {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-confirm-totp-03, token different, %v err %v", claims.Subject, err)
		return
	}
	err = updateTOTPVerified(claims.Subject, timeNow())
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-confirm-totp-04, DB select, %v err %v", claims.Subject, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func setupSMS(w http.ResponseWriter, r *http.Request, claims *TokenClaims) {
	vars := mux.Vars(r)
	sms, err := url.QueryUnescape(vars["sms"])
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-setup-sms-01, query unescape sms %v err: %v", vars["sms"], err)
		return
	}

	secret, err := genToken()
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-setup-sms-02, RND %v err %v", claims.Subject, err)
		return
	}

	err = updateSMS(claims.Subject, secret, sms)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-setup-sms-03, updateSMS failed %v err %v", claims.Subject, err)
		return
	}

	totp := newTOTP(secret)

	url := strings.Replace(opts.UrlSms, "{sms}", sms, 1)
	url = strings.Replace(url, "{token}", totp.Now(), 1)

	err = sendSMS(url)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-setup-sms-04, send SMS failed %v err %v", claims.Subject, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func confirmSMS(w http.ResponseWriter, r *http.Request, claims *TokenClaims) {
	vars := mux.Vars(r)
	token, err := url.QueryUnescape(vars["token"])
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-confirm-sms-01, query unescape token %v err: %v", vars["token"], err)
		return
	}

	result, err := findAuthByEmail(claims.Subject)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-confirm-sms-02, DB select, %v err %v", claims.Subject, err)
		return
	}

	totp := newTOTP(*result.totp)
	if token != totp.Now() {
		writeErr(w, http.StatusUnauthorized, "invalid_request", "blocked", "ERR-confirm-sms-03, token different, %v err %v", claims.Subject, err)
		return
	}
	err = updateSMSVerified(claims.Subject, timeNow())
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-confirm-sms-04, update sms failed, %v err %v", claims.Subject, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func readiness(w http.ResponseWriter, _ *http.Request) {
	err := db.Ping()
	if err != nil {
		log.Printf(fmt.Sprintf("not ready: %v", err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func liveness(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func jwkFunc(w http.ResponseWriter, _ *http.Request) {
	json := []byte(`{"keys":[`)
	if privRSA != nil {
		k := jose.JSONWebKey{Key: privRSA.Public()}
		kid, err := k.Thumbprint(crypto.SHA256)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-jwk-1, %v", err)
			return
		}
		k.KeyID = hex.EncodeToString(kid)
		mj, err := k.MarshalJSON()
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-jwk-2, %v", err)
			return
		}
		json = append(json, mj...)
	}
	if privEdDSA != nil {
		k := jose.JSONWebKey{Key: privEdDSA.Public()}
		mj, err := k.MarshalJSON()
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-jwk-3, %v", err)
			return
		}
		json = append(json, []byte(`,`)...)
		json = append(json, mj...)
	}
	json = append(json, []byte(`]}`)...)

	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	w.Write(json)
}

//****************** OAuth

func refresh(w http.ResponseWriter, r *http.Request) {
	contentType := r.Header.Get("Content-type")
	var refreshToken string
	var err error
	if strings.Index(contentType, "application/json") >= 0 {
		refreshToken, err = paramJson("refresh_token", r)
	} else {
		refreshToken, err = param("refresh_token", r)
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-oauth-01, basic auth failed")
		return
	}
	if refreshToken == "" {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-oauth-02, no refresh token")
		return
	}

	refreshClaims, err := checkRefreshToken(refreshToken)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_grant", "blocked", "ERR-oauth-03, cannot verify refresh token %v", err)
		return
	}

	encodedAccessToken, encodedRefreshToken, expiresAt, err := checkRefresh(refreshClaims.Subject, refreshClaims.Token)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_grant", "blocked", "ERR-oauth-03, cannot verify refresh token %v", err)
		return
	}

	oauth := OAuth{AccessToken: encodedAccessToken, TokenType: "Bearer", RefreshToken: encodedRefreshToken, Expires: strconv.FormatInt(expiresAt, 10)}
	oauthEnc, err := json.Marshal(oauth)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_grant", "blocked", "ERR-oauth-04, cannot verify refresh token %v", err)
		return
	}
	w.Write(oauthEnc)
}

func oauth(w http.ResponseWriter, r *http.Request) {
	grantType, err := param("grant_type", r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-oauth-01, basic auth failed")
		return
	}

	switch grantType {
	case "refresh_token":
		refresh(w, r)
	case "client_credentials":
		user, err := basicAuth(r)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "Basic auth failed: %v", err)
			return
		}

		encodedAccessToken, err := encodeAccessToken(user, opts.Scope, opts.Audience, opts.Issuer, nil)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "Basic auth failed: %v", err)
			return
		}

		oauth := OAuthSystem{
			AccessToken: encodedAccessToken,
			TokenType:   "Bearer",
		}
		oauthEnc, err := json.Marshal(oauth)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_grant", "blocked", "ERR-oauth-08, cannot verify refresh token %v", err)
			return
		}
		w.Write(oauthEnc)

	case "authorization_code":
		code, err := param("code", r)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-oauth-01, basic auth failed")
			return
		}
		codeVerifier, err := param("code_verifier", r)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-oauth-01, basic auth failed")
			return
		}
		//https://tools.ietf.org/html/rfc7636#section-4.1 length must be <= 43 <= 128
		if len(codeVerifier) < 43 {
			writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-oauth-01, min 43 chars")
			return
		}
		if len(codeVerifier) > 128 {
			writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-oauth-01, max 128 chars")
			return
		}
		cc, err := checkCodeToken(code)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-oauth-04, code check failed: %v", err)
			return
		}
		if cc.CodeCodeChallengeMethod == "S256" {
			h := sha256.Sum256([]byte(codeVerifier))
			s := base64.RawURLEncoding.EncodeToString(h[:])
			if cc.CodeChallenge != s {
				writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-oauth-04, auth challenge failed")
				return
			}
		} else {
			writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-oauth-04, only S256 supported")
			return
		}

		result, err := findAuthByEmail(cc.Subject)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-writeOAuth, findAuthByEmail for %v failed, %v", cc.Subject, err)
			return
		}

		writeOAuth(w, result)
	case "password":
		if !opts.PasswordFlow {
			writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-oauth-05a, no username")
			return
		}
		email, err := param("username", r)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-oauth-05a, no username")
			return
		}
		password, err := param("password", r)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-oauth-05b, no password")
			return
		}
		scope, err := param("scope", r)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-oauth-05c, no scope")
			return
		}
		if email == "" || password == "" || scope == "" {
			writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-oauth-05, username, password, or scope empty")
			return
		}

		result, errString, err := checkEmailPassword(email, password)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_grant", errString, "ERR-oauth-06 %v", err)
			return
		}

		writeOAuth(w, result)
	default:
		writeErr(w, http.StatusBadRequest, "unsupported_grant_type", "blocked", "ERR-oauth-09, unsupported grant type")
	}
}

// https://tools.ietf.org/html/rfc6749#section-1.3.1
// https://developer.okta.com/blog/2019/08/22/okta-authjs-pkce
func authorize(w http.ResponseWriter, r *http.Request) {
	keys := r.URL.Query()
	rt := keys.Get("response_type")
	email := keys.Get("email")
	if rt == flowCode && email != "" {
		handleCode(w, keys.Get("email"),
			keys.Get("code_challenge"),
			keys.Get("code_challenge_method"),
			keys.Get("redirect_uri"), false)
	} else {
		http.ServeFile(w, r, "login.html")
	}
}

func revoke(w http.ResponseWriter, r *http.Request) {
	tokenHint, err := param("token_type_hint", r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "unsupported_grant_type1", "blocked", "ERR-oauth-07, unsupported grant type")
		return
	}
	if tokenHint == "refresh_token" {
		oldToken, err := param("token", r)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "unsupported_grant_type1", "blocked", "ERR-oauth-07, unsupported grant type")
			return
		}
		if oldToken == "" {
			writeErr(w, http.StatusBadRequest, "unsupported_grant_type1", "blocked", "ERR-oauth-07, unsupported grant type")
			return
		}
		_, err = resetRefreshToken(oldToken)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "unsupported_grant_type2", "blocked", "ERR-oauth-07, unsupported grant type")
			return
		}
	} else {
		writeErr(w, http.StatusBadRequest, "unsupported_grant_type", "blocked", "ERR-oauth-07, unsupported grant type")
		return
	}
}

func logout(w http.ResponseWriter, r *http.Request, claims *TokenClaims) {
	keys := r.URL.Query()
	ru := keys.Get("redirect_uri")

	result, err := findAuthByEmail(claims.Subject)
	if err != nil {
		if ru != "" {
			log.Printf("ERR-oauth-06 %v", err)
			w.Header().Set("Location", ru)
			w.WriteHeader(http.StatusSeeOther)
		} else {
			writeErr(w, http.StatusBadRequest, "invalid_grant", "not-found", "ERR-oauth-06 %v", err)
		}
		return
	}

	refreshToken := result.refreshToken
	_, err = resetRefreshToken(refreshToken)
	if err != nil {
		if ru != "" {
			log.Printf("ERR-oauth-07, unsupported grant type: %v", err)
			w.Header().Set("Location", ru)
			w.WriteHeader(http.StatusSeeOther)
		} else {
			writeErr(w, http.StatusBadRequest, "unsupported_grant_type", "blocked", "ERR-oauth-07, unsupported grant type: %v", err)
		}
		return
	}

	if ru != "" {
		w.Header().Set("Location", ru)
		w.WriteHeader(http.StatusSeeOther)
	} else {
		w.WriteHeader(http.StatusOK)
	}
}

func serverTime(w http.ResponseWriter, r *http.Request, email string) {
	currentTime := timeNow()
	writeJsonStr(w, `{"time":"`+currentTime.Format("2006-01-02 15:04:05")+`","offset":`+strconv.Itoa(secondsAdd)+`}`)
}

func timeWarp(w http.ResponseWriter, r *http.Request, adminEmail string) {
	m := mux.Vars(r)
	h := m["hours"]
	if h == "" {
		writeErr(w, http.StatusBadRequest, "invalid_grant", "not-found", "ERR-timewarp-01 %v", m)
		return
	}
	hours, err := strconv.Atoi(h)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_grant", "not-found", "ERR-timewarp-02 %v", err)
		return
	}

	seconds := hours * 60 * 60
	secondsAdd += seconds
	log.Printf("time warp: %v", timeNow())

	//since we warp, the token will be invalid
	result, err := findAuthByEmail(adminEmail)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-timeWarp, findAuthByEmail for %v failed, %v", adminEmail, err)
		return
	}
	writeOAuth(w, result)
}

func asUser(w http.ResponseWriter, r *http.Request, _ string) {
	m := mux.Vars(r)
	email := m["email"]
	result, err := findAuthByEmail(email)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-writeOAuth, findAuthByEmail for %v failed, %v", email, err)
		return
	}
	writeOAuth(w, result)
}

func deleteUser(w http.ResponseWriter, r *http.Request, admin string) {
	m := mux.Vars(r)
	email := m["email"]
	err := deleteDbUser(email)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_grant", "not-found", "could not delete user %v, requested by %s", err, admin)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func updateUser(w http.ResponseWriter, r *http.Request, admin string) {
	//now we update the meta data that comes as system meta data. Thus we trust the system to provide the correct metadata, not the user
	m := mux.Vars(r)
	email := m["email"]
	b, err := io.ReadAll(r.Body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_grant", "not-found", "could not update user %v, requested by %s", err, admin)
		return
	}
	if !json.Valid(b) {
		writeErr(w, http.StatusBadRequest, "invalid_grant", "not-found", "invalid json [%s], requested by %s", string(b), admin)
		return
	}
	err = updateSystemMeta(email, string(b))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_grant", "not-found", "could not update system meta %v, requested by %s", err, admin)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeJsonStr(w http.ResponseWriter, obj string) {
	w.Header().Set("Content-Type", "application/json")
	_, err := w.Write([]byte(obj))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_grant", "not-found", "Could write json: %v", err)
	}
}
