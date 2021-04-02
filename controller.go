package main

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/gorilla/schema"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/text/language"
	"gopkg.in/square/go-jose.v2"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type EmailRequest struct {
	MailTo      string `json:"mail_to,omitempty"`
	Subject     string `json:"subject"`
	TextMessage string `json:"text_message"`
	HtmlMessage string `json:"html_message"`
}

type EmailToken struct {
	Email string `json:"email"`
	Token string `json:"token"`
}

type EmailInvite struct {
	Email       string    `json:"email"`
	InviteEmail string    `json:"invite_email"`
	InvitedAt   time.Time `json:"invited_at"`
	Org         string    `json:"org"`
}

type scryptParam struct {
	n   int
	r   int
	p   int
	len int
}

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

	result, err := dbSelect(email)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-confirm-email-02, update email token for %v failed, token %v: %v", email, token, err)
		return
	}

	encodedAccessToken, encodedRefreshToken, expiresAt, err := encodeTokens(result, email)
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

	err = updateEmailToken(et.Email, et.Token)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-confirm-email-01, update email token for %v failed, token %v: %v", et.Email, et.Token, err)
		return
	}

	result, err := dbSelect(et.Email)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-confirm-email-02, update email token for %v failed, token %v: %v", et.Email, et.Token, err)
		return
	}

	encodedAccessToken, encodedRefreshToken, expiresAt, err := encodeTokens(result, et.Email)
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

//don't forget to refresh the token, this updates the token content
func inviteResetMyToken(w http.ResponseWriter, _ *http.Request, claims *TokenClaims) {
	inviteToken, err := genToken()
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-invite-04, RND %v err %v", claims.Subject, err)
		return
	}
	err = updateInviteToken(claims.Subject, inviteToken)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-invite-06, insert user failed: %v", err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func invitations(w http.ResponseWriter, _ *http.Request, claims *TokenClaims) {
	invites, err := dbInvitations(claims.Subject)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-invite-06, insert user failed: %v", err)
		return
	}

	oauthEnc, err := json.Marshal(invites)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_grant", "blocked", "ERR-oauth-08, cannot verify refresh token %v", err)
		return
	}
	w.Write(oauthEnc)
}

func inviteMyUpdate(w http.ResponseWriter, r *http.Request, claims *TokenClaims) {
	vars := mux.Vars(r)
	email, err := url.QueryUnescape(vars["email"])
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-confirm-reset-email-01, query unescape email %v err: %v", vars["email"], err)
		return
	}
	token, err := url.QueryUnescape(vars["token"])
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-confirm-reset-email-01, query unescape email %v err: %v", vars["email"], err)
		return
	}
	date, err := url.QueryUnescape(vars["date"])
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-confirm-reset-email-01, query unescape email %v err: %v", vars["email"], err)
		return
	}
	other, err := dbSelect(email)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-confirm-reset-email-01, query unescape email %v err: %v", vars["email"], err)
		return
	}

	decoded, err := base32.StdEncoding.DecodeString(token)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-confirm-reset-email-01, query unescape email %v err: %v", vars["email"], err)
		return
	}

	//hardcode version to 0
	decoded[0] = 0
	//token is contributor email, validity date, sponsor email
	storedPw, calcPw, err := checkPw(claims.Subject+date+other.inviteToken, decoded)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-confirm-reset-email-01, query unescape email %v err: %v", vars["email"], err)
		return
	}
	if bytes.Compare(calcPw, storedPw) != 0 {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-confirm-reset-email-01, query unescape email %v err: %v", vars["email"], err)
		return
	}

	layout := "2006-01-02"
	t, err := time.Parse(layout, date)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-invite-06, insert user failed: %v", err)
		return
	}
	if t.Add(time.Second * time.Duration(opts.ExpireInvite)).Before(timeNow()) {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-invite-06, insert user failed: %v", err)
		return
	}

	err = updateInvite(claims.Subject, email)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-invite-06, insert user failed: %v", err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func inviteOtherDelete(w http.ResponseWriter, r *http.Request, claims *TokenClaims) {
	//delete the invite from me of other users
	vars := mux.Vars(r)
	email, err := url.QueryUnescape(vars["email"])
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-confirm-reset-email-01, query unescape email %v err: %v", vars["email"], err)
		return
	}
	err = deleteInvite(claims.Subject, email, claims.InviteToken)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-invite-06, insert user failed: %v", err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func inviteMyDelete(w http.ResponseWriter, _ *http.Request, claims *TokenClaims) {
	err := deleteMyInvite(claims.Subject)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-invite-06, insert user failed: %v", err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func inviteOtherDeletePending(w http.ResponseWriter, r *http.Request, claims *TokenClaims) {
	vars := mux.Vars(r)
	email, err := url.QueryUnescape(vars["email"])
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-confirm-reset-email-01, query unescape email %v err: %v", vars["email"], err)
		return
	}
	err = deletePendingInvite(email, claims.Subject)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-invite-06, insert user failed: %v", err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func inviteOther(w http.ResponseWriter, r *http.Request, claims *TokenClaims) {
	buf, _ := ioutil.ReadAll(r.Body)
	rdr1 := ioutil.NopCloser(bytes.NewBuffer(buf))
	rdr2 := ioutil.NopCloser(bytes.NewBuffer(buf))

	var e EmailInvite
	err := json.NewDecoder(rdr1).Decode(&e)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-invite-01, cannot parse JSON credentials %v", err)
		return
	}

	err = validateEmail(e.Email)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-invite-02, email is wrong %v", err)
		return
	}

	err = validateEmail(e.InviteEmail)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-invite-03, email is wrong %v", err)
		return
	}

	emailToken, err := genToken()
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-invite-04, RND %v err %v", e.Email, err)
		return
	}
	refreshToken, err := genToken()
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-invite-04, RND %v err %v", e.Email, err)
		return
	}
	inviteToken, err := genToken()
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-invite-04, RND %v err %v", e.Email, err)
		return
	}

	err = insertUser(e.Email, nil, nil, emailToken, refreshToken, inviteToken, &e.InviteEmail, &e.InvitedAt)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-invite-06, insert user failed: %v", err)
		return
	}

	var other map[string]string
	err = json.NewDecoder(rdr2).Decode(&other)
	if err != nil {
		log.Printf("No or wrong json, ignoring [%v]", err)
	}
	other["token"] = emailToken

	subject := parseTemplate("template-subject-signup_"+lang(r)+".tmpl", other)
	if subject == "" {
		subject = "You have been invited, activate your account"
	}
	textMessage := parseTemplate("template-plain-signup_"+lang(r)+".tmpl", other)
	if textMessage == "" {
		textMessage = "Click on this link " + opts.EmailLinkPrefix +
			"/confirm/invite/" + url.QueryEscape(e.Email) + "/" + emailToken + "/" + url.QueryEscape(e.InviteEmail) + "/"
	}
	htmlMessage := parseTemplate("template-html-signup_"+lang(r)+".tmpl", other)

	req := EmailRequest{
		MailTo:      url.QueryEscape(e.Email),
		Subject:     subject,
		TextMessage: textMessage,
		HtmlMessage: htmlMessage,
	}

	url := strings.Replace(opts.EmailUrl, "{email}", url.QueryEscape(e.Email), 1)
	url = strings.Replace(url, "{token}", emailToken, 1)

	go func() {
		err = sendEmail(url, req)
		if err != nil {
			log.Printf("ERR-signup-07, send email failed: %v, %v\n", url, err)
		}
	}()

	err = insertAudit(e.Email, "MAIL_SENT")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-signup-08, db update failed: %v", err)
		return
	}
	w.WriteHeader(http.StatusOK)

}

func signup(w http.ResponseWriter, r *http.Request) {
	buf, _ := ioutil.ReadAll(r.Body)
	rdr1 := ioutil.NopCloser(bytes.NewBuffer(buf))
	rdr2 := ioutil.NopCloser(bytes.NewBuffer(buf))

	var cred Credentials
	err := json.NewDecoder(rdr1).Decode(&cred)
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
	inviteToken, err := genToken()
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-invite-04, RND %v err %v", cred.Email, err)
		return
	}

	err = insertUser(cred.Email, calcPw, nil, emailToken, refreshToken, inviteToken, nil, nil)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-signup-07, insert user failed: %v", err)
		return
	}

	var other map[string]string
	err = json.NewDecoder(rdr2).Decode(&other)
	if err != nil {
		log.Printf("No or wrong json, ignoring [%v]", err)
	}
	other["token"] = emailToken

	subject := parseTemplate("template-subject-signup_"+lang(r)+".tmpl", other)
	if subject == "" {
		subject = "Validate your email"
	}
	textMessage := parseTemplate("template-plain-signup_"+lang(r)+".tmpl", other)
	if textMessage == "" {
		textMessage = "Click on this link " + opts.EmailLinkPrefix + "/confirm/signup/" + url.QueryEscape(cred.Email) + "/" + emailToken
	}
	htmlMessage := parseTemplate("template-html-signup_"+lang(r)+".tmpl", other)

	e := EmailRequest{
		MailTo:      url.QueryEscape(cred.Email),
		Subject:     subject,
		TextMessage: textMessage,
		HtmlMessage: htmlMessage,
	}

	url := strings.Replace(opts.EmailUrl, "{email}", url.QueryEscape(cred.Email), 1)
	url = strings.Replace(url, "{token}", emailToken, 1)

	go func() {
		err = sendEmail(url, e)
		if err != nil {
			log.Printf("ERR-signup-07, send email failed: %v, %v\n", url, err)
		}
	}()

	err = insertAudit(cred.Email, "MAIL_SENT")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-signup-09, db update failed: %v", err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func lang(r *http.Request) string {
	accept := r.Header.Get("Accept-Language")
	tag, _ := language.MatchStrings(matcher, accept)
	b, _ := tag.Base()
	return b.String()
}

func parseTemplate(filename string, other map[string]string) string {
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
	if result.totp != nil && result.sms != nil && result.smsVerified > 0 {
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
			writeErr(w, http.StatusTeapot, "invalid_client", "blocked", "ERR-login-08, waiting for sms verification: %v", cred.Email)
			return
		} else if token != cred.TOTP {
			writeErr(w, http.StatusForbidden, "invalid_request", "blocked", "ERR-login-09, sms wrong token, %v err %v", cred.Email, err)
			return
		}
	}

	//TOTP logic
	if result.totp != nil && result.totpVerified > 0 {
		totp := newTOTP(*result.totp)
		token := totp.Now()
		if token != cred.TOTP {
			writeErr(w, http.StatusForbidden, "invalid_request", "blocked", "ERR-login-10, totp wrong token, %v err %v", cred.Email, err)
			return
		}
	}

	if cred.CodeCodeChallengeMethod != "" {
		//return the code flow
		encoded, _, err := encodeCodeToken(cred.Email, cred.CodeChallenge, cred.CodeCodeChallengeMethod)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "invalid_request", "blocked", "ERR-login-14, cannot set refresh token for %v, %v", cred.Email, err)
			return
		}
		w.Header().Set("Location", cred.RedirectUri+"?code="+encoded)
		w.WriteHeader(303)
	} else {
		refreshToken, err := resetRefreshToken(result.refreshToken, cred.Email)
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
	fmt.Printf("Sent to NR %s token [%s]\n", sms, token)
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

	var other map[string]string
	err = json.NewDecoder(r.Body).Decode(&other)
	if err != nil {
		log.Printf("No or wrong json, ignoring [%v]", err)
	}

	subject := parseTemplate("template-subject-reset_"+lang(r)+".tmpl", other)
	if subject == "" {
		subject = "Reset your email"
	}
	textMessage := parseTemplate("template-plain-reset_"+lang(r)+".tmpl", other)
	if textMessage == "" {
		textMessage = "Click on this link " + opts.EmailLinkPrefix + "/confirm/reset/" + email + "/" + forgetEmailToken
	}
	htmlMessage := parseTemplate("template-html-reset_"+lang(r)+".tmpl", other)

	e := EmailRequest{
		MailTo:      email,
		Subject:     subject,
		TextMessage: textMessage,
		HtmlMessage: htmlMessage,
	}

	url := strings.Replace(opts.EmailUrl, "{email}", email, 1)
	url = strings.Replace(url, "{token}", forgetEmailToken, 1)

	go func() {
		err = sendEmail(url, e)
		if err != nil {
			log.Printf("ERR-reset-email-04, send email failed: %v", url)
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
	confirmGeneric(w, r, false)
}

func confirmInvite(w http.ResponseWriter, r *http.Request) {
	confirmGeneric(w, r, true)
}

func confirmGeneric(w http.ResponseWriter, r *http.Request, invite bool) {
	var cred Credentials
	err := json.NewDecoder(r.Body).Decode(&cred)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-signup-01, cannot parse JSON credentials %v", err)
		return
	}

	calcPw, err := newPw(cred.Password, 0)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-signup-05, key %v error: %v", cred.Email, err)
		return
	}

	if invite {
		err = resetPasswordInvite(cred.Email, cred.EmailToken, calcPw)
	} else {
		err = resetPassword(cred.Email, cred.EmailToken, calcPw)
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-confirm-reset-email-07, update user failed: %v", err)
		return
	}

	result, err := dbSelect(cred.Email)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-confirm-reset-email-08, update email token for %v failed, token %v: %v", cred.Email, cred.EmailToken, err)
		return
	}

	encodedAccessToken, encodedRefreshToken, expiresAt, err := encodeTokens(result, cred.Email)
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
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(p)
}

func confirmTOTP(w http.ResponseWriter, r *http.Request, claims *TokenClaims) {
	vars := mux.Vars(r)
	token, err := url.QueryUnescape(vars["token"])
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-confirm-totp-01, query unescape token %v err: %v", vars["token"], err)
		return
	}

	result, err := dbSelect(claims.Subject)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-confirm-totp-02, DB select, %v err %v", claims.Subject, err)
		return
	}

	totp := newTOTP(*result.totp)
	if token != totp.Now() {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-confirm-totp-03, token different, %v err %v", claims.Subject, err)
		return
	}
	err = updateTOTPVerified(claims.Subject)
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

	result, err := dbSelect(claims.Subject)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-confirm-sms-02, DB select, %v err %v", claims.Subject, err)
		return
	}

	totp := newTOTP(*result.totp)
	if token != totp.Now() {
		writeErr(w, http.StatusUnauthorized, "invalid_request", "blocked", "ERR-confirm-sms-03, token different, %v err %v", claims.Subject, err)
		return
	}
	err = updateSMSVerified(claims.Subject)
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
	if grantType == "refresh_token" {
		err := basic(w, r)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-oauth-01, basic auth failed")
			return
		}
		refresh(w, r)
		return

	} else if grantType == "authorization_code" {
		err := basic(w, r)
		if err != nil {
			clientId, err := param("client_id", r)
			if err != nil {
				writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-oauth-01, basic auth failed")
				return
			}
			clientSecret, err := param("client_secret", r)
			if err != nil {
				writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-oauth-01, basic auth failed")
				return
			}
			if clientId != opts.OAuthUser || clientSecret != opts.OAuthPass {
				writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-oauth-04, basic auth failed")
				return
			}
		}

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
			writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-oauth-04, basic auth failed")
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

		result, err := dbSelect(cc.Subject)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_grant", "not-found", "ERR-oauth-06 %v", err)
			return
		}

		encodedAccessToken, encodedRefreshToken, expiresAt, err := encodeTokens(result, cc.Subject)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_grant", "blocked", "ERR-oauth-07, cannot verify refresh token %v", err)
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
		return

	} else if grantType == "password" && opts.PasswordFlow {
		err := basic(w, r)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-oauth-04, basic auth failed")
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

		encodedAccessToken, encodedRefreshToken, expiresAt, err := encodeTokens(result, email)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_grant", "blocked", "ERR-oauth-07, cannot verify refresh token %v", err)
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
		return

	} else {
		writeErr(w, http.StatusBadRequest, "unsupported_grant_type", "blocked", "ERR-oauth-09, unsupported grant type")
		return
	}
}

//https://tools.ietf.org/html/rfc6749#section-1.3.1
//https://developer.okta.com/blog/2019/08/22/okta-authjs-pkce
func authorize(w http.ResponseWriter, r *http.Request) {
	responseType, err := param("response_type", r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_grant", "blocked", "ERR-oauth-06 %v", err)
		return
	}
	if responseType == "code" {
		http.ServeFile(w, r, "login.html")
		return
	}
	writeErr(w, http.StatusBadRequest, "unsupported_grant_type", "blocked", "ERR-oauth-07, unsupported grant type")
}

func revoke(w http.ResponseWriter, r *http.Request, claims *TokenClaims) {
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
		_, err = resetRefreshToken(oldToken, claims.Subject)
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
	result, err := dbSelect(claims.Subject)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_grant", "not-found", "ERR-oauth-06 %v", err)
		return
	}

	refreshToken := result.refreshToken
	_, err = resetRefreshToken(refreshToken, claims.Subject)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "unsupported_grant_type", "blocked", "ERR-oauth-07, unsupported grant type")
		return
	}

	if len(r.URL.Query()["redirect_uri"]) > 0 {
		w.Header().Set("Location", r.URL.Query()["redirect_uri"][0])
		w.WriteHeader(http.StatusSeeOther)
	} else {
		w.WriteHeader(http.StatusOK)
	}
}

func timeWarp(w http.ResponseWriter, r *http.Request) {
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

	hoursAdd += hours
	log.Printf("time warp: %v", timeNow())
	w.WriteHeader(http.StatusOK)
}
