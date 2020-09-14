package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/dimiro1/banner"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/jessevdk/go-flags"
	_ "github.com/mattn/go-sqlite3"
	"github.com/xlzd/gotp"
	"golang.org/x/crypto/scrypt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	options    *Opts
	jwtKey     = []byte(os.Getenv("FFS_KEY"))
	db         *sql.DB
	tokenExp   time.Duration
	refreshExp time.Duration
)

const (
	version = "1.0.0"
)

type Opts struct {
	Issuer    string `short:"i" long:"issuer" description:"Name of this issuer" default:"DevIssuer"`
	Port      int    `short:"p" long:"port" description:"Port to listen on" default:"8080"`
	DBPath    string `long:"db" description:"Path to the DB file" default:"."`
	UrlEmail  string `short:"u" long:"url" description:"URL to email service, e.g., https://email.com/send/email/{action}/{email}/{token}" default:"http://localhost:8080/send/email/{action}/{email}/{token}"`
	UrlSMS    string `short:"s" long:"sms" description:"URL to email service, e.g., https://sms.com/send/sms/{sms}/{token}" default:"http://localhost:8080/send/sms/{sms}/{token}"`
	Audience  string `short:"a" long:"aud" description:"Audience comma separated string, e.g., FFS_FE, FFS_DB"`
	Expires   int    `short:"t" long:"tokenExpires" description:"Token expiration minutes, e.g., 60" default:"60"`
	Refresh   int    `short:"r" long:"refreshExpires" description:"Refresh token expiration days, e.g., 7" default:"7"`
	OAuthUser string `long:"oauthPass" description:"OAuth username for HTTP BasicAuth to access the endpoint" default:"user"`
	OAuthPass string `long:"oauthUser" description:"OAuth password for HTTP BasicAuth to access the endpoint" default:"pass"`
	Dev       bool   `short:"d" long:"dev" description:"Developer mode"`
}

type Credentials struct {
	Email    string `json:"email,omitempty"`
	Password string `json:"password"`
	TOTP     string `json:"totp,omitempty"`
}

type TokenClaims struct {
	Role string `json:"role,omitempty"`
	jwt.StandardClaims
}
type RefreshClaims struct {
	ExpiresAt int64  `json:"exp,omitempty"`
	Subject   string `json:"role,omitempty"`
	Token     string `json:"token,omitempty"`
}
type ProvisioningUri struct {
	Uri string `json:"uri"`
}

func (r *RefreshClaims) Valid() error {
	now := time.Now().Unix()
	if r.ExpiresAt < now {
		return fmt.Errorf("expired by %vs", now-r.ExpiresAt)
	}
	return nil
}

func auth(next func(w http.ResponseWriter, r *http.Request, claims *TokenClaims)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		authorizationHeader := r.Header.Get("Authorization")
		if authorizationHeader != "" {
			bearerToken := strings.Split(authorizationHeader, " ")
			if len(bearerToken) == 2 {
				claims := &TokenClaims{}
				token, err := jwt.ParseWithClaims(bearerToken[1], claims, func(token *jwt.Token) (i interface{}, err error) {
					return jwtKey, nil
				})

				if err != nil || !token.Valid {
					writeErr(w, http.StatusForbidden, "ERR-auth-01, could not parse token: %v", bearerToken[1])
					return
				}

				next(w, r, claims)
				return
			} else {
				writeErr(w, http.StatusForbidden, "ERR-auth-02, could not split token: %v", bearerToken[1])
				return
			}
		}
		writeErr(w, http.StatusBadRequest, "ERR-auth-03, authorization header not set")
		return
	}
}

func refresh(w http.ResponseWriter, r *http.Request) {
	//https://medium.com/monstar-lab-bangladesh-engineering/jwt-auth-in-go-part-2-refresh-tokens-d334777ca8a0

	//check if refresh token matches
	c, err := r.Cookie("refresh")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "ERR-refresh-01, cookie not found: %v", err)
		return
	}
	accessToken, refreshToken, expiresAt, err := refresh0(c.Value)
	if err != nil {
		writeErr(w, http.StatusForbidden, "ERR-refresh %v", err)
		return
	}
	w.Header().Set("Token", accessToken)

	cookie := http.Cookie{
		Name:     "refresh",
		Value:    refreshToken,
		Path:     "/refresh",
		HttpOnly: true,
		Secure:   !options.Dev,
		Expires:  time.Unix(expiresAt, 0),
	}
	w.Header().Set("Set-Cookie", cookie.String())
	w.WriteHeader(http.StatusOK)
}
func refresh0(token string) (string, string, int64, error) {
	refreshClaims := &RefreshClaims{}

	refreshToken, err := jwt.ParseWithClaims(token, refreshClaims, func(token *jwt.Token) (i interface{}, err error) {
		return jwtKey, nil
	})

	if err != nil || !refreshToken.Valid {
		return "", "", 0, fmt.Errorf("ERR-refresh-02, could not parse token %v", err)
	}

	result, err := dbSelect(refreshClaims.Subject)
	if err != nil {
		return "", "", 0, fmt.Errorf("ERR-refresh-03, DB select, %v err %v", refreshClaims.Subject, err)
	}

	if result.emailVerified == nil || result.emailVerified.Unix() == 0 {
		return "", "", 0, fmt.Errorf("ERR-refresh-04, user %v no email verified: %v", refreshClaims.Subject, err)
	}

	if result.refreshToken == nil || refreshClaims.Token != *result.refreshToken {
		return "", "", 0, fmt.Errorf("ERR-refresh-05, refresh token mismatch %v != %v", refreshClaims.Token, *result.refreshToken)
	}

	accessTokenString, err := setAccessToken(string(result.role), result.id, refreshClaims.Subject)
	if err != nil {
		return "", "", 0, fmt.Errorf("ERR-refresh-06, cannot set access token for %v, %v", refreshClaims.Subject, err)
	}

	refreshTokenString, expiresAt, err := setRefreshToken(refreshClaims.Subject, *result.refreshToken)
	if err != nil {
		return "", "", 0, fmt.Errorf("ERR-refresh-07, cannot set refresh token for %v, %v", refreshClaims.Subject, err)
	}
	return accessTokenString, refreshTokenString, expiresAt, nil
}

func confirmEmail(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	token := vars["token"]
	email := vars["email"]

	err := updateEmailToken(email, token)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ERR-confirm-email-01, update email token for %v failed, token %v: %v", email, token, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func signup(w http.ResponseWriter, r *http.Request) {
	var cred Credentials
	err := json.NewDecoder(r.Body).Decode(&cred)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ERR-signup-01, cannot parse JSON credentials %v", err)
		return
	}

	err = validateEmail(cred.Email)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ERR-signup-02, email is wrong %v", err)
		return
	}

	err = validatePassword(cred.Password)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ERR-signup-03, password is wrong %v", err)
		return
	}

	rnd, err := genRnd(32)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "ERR-signup-04, RND %v err %v", cred.Email, err)
		return
	}
	emailToken := base32.StdEncoding.EncodeToString(rnd[0:16])

	//https://security.stackexchange.com/questions/11221/how-big-should-salt-be

	salt := rnd[16:32]
	dk, err := scrypt.Key([]byte(cred.Password), salt, 16384, 8, 1, 32)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "ERR-signup-05, key %v error: %v", cred.Email, err)
		return
	}

	err = insertUser(salt, cred.Email, dk, emailToken)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ERR-signup-06, insert user failed: %v", err)
		return
	}

	url := strings.Replace(options.UrlEmail, "{email}", url.QueryEscape(cred.Email), 1)
	url = strings.Replace(url, "{token}", emailToken, 1)
	url = strings.Replace(url, "{action}", "signup", 1)

	err = sendEmail(url)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ERR-signup-07, send email failed: %v", url)
		return
	}

	err = updateMailStatus(cred.Email)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ERR-signup-08, db update failed: %v", err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func checkEmailPassword(email string, password string) (*dbRes, error) {
	err := validateEmail(email)
	if err != nil {
		return nil, fmt.Errorf("ERR-login-02, email is wrong %v", err)
	}

	result, err := dbSelect(email)
	if err != nil {
		return nil, fmt.Errorf("ERR-login-03, DB select, %v err %v", email, err)
	}

	if result.emailVerified == nil || result.emailVerified.Unix() == 0 {
		return nil, fmt.Errorf("ERR-login-04, user %v no email verified: %v", email, err)
	}

	dk, err := scrypt.Key([]byte(password), result.salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("ERR-login-05, key %v error: %v", email, err)
	}

	if bytes.Compare(dk, result.password) != 0 {
		return nil, fmt.Errorf("ERR-login-06, user %v password mismatch", email)
	}
	return result, nil
}

func login(w http.ResponseWriter, r *http.Request) {
	login0(w, r)
}

func login0(w http.ResponseWriter, r *http.Request) {
	var cred Credentials
	err := json.NewDecoder(r.Body).Decode(&cred)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ERR-login-01, cannot parse JSON credentials %v", err)
		return
	}

	result, err := checkEmailPassword(cred.Email, cred.Password)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ERR-login-02 %v", err)
		return
	}

	//SMS logic
	if result.totp != nil && result.sms != nil && result.smsVerified != nil {
		totp := newTOTP(*result.totp)
		token := totp.Now()
		if cred.TOTP == "" {
			url := strings.Replace(options.UrlSMS, "{sms}", *result.sms, 1)
			url = strings.Replace(url, "{token}", token, 1)
			err = sendSMS(url)
			if err != nil {
				writeErr(w, http.StatusUnauthorized, "ERR-login-07, send sms failed %v error: %v", cred.Email, err)
				return
			}
			writeErr(w, http.StatusTeapot, "ERR-login-08, waiting for sms verification: %v", cred.Email)
			return
		} else if token != cred.TOTP {
			writeErr(w, http.StatusForbidden, "ERR-login-09, sms wrong token, %v err %v", cred.Email, err)
			return
		}
	}

	//TOTP logic
	if result.totp != nil && result.totpVerified != nil {
		totp := newTOTP(*result.totp)
		token := totp.Now()
		if token != cred.TOTP {
			writeErr(w, http.StatusForbidden, "ERR-login-10, totp wrong token, %v err %v", cred.Email, err)
			return
		}
	}

	accessToken, err := setAccessToken(string(result.role), result.id, cred.Email)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "ERR-login-11, cannot set access token for %v, %v", cred.Email, err)
		return
	}
	refreshToken, expiresAt, err := setRefreshToken(cred.Email, *result.refreshToken)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "ERR-login-12, cannot set refresh token for %v, %v", cred.Email, err)
		return
	}

	w.Header().Set("Token", accessToken)

	cookie := http.Cookie{
		Name:     "refresh",
		Value:    refreshToken,
		Path:     "/refresh",
		HttpOnly: true,
		Secure:   !options.Dev,
		Expires:  time.Unix(expiresAt, 0),
	}
	w.Header().Set("Set-Cookie", cookie.String())
	w.WriteHeader(http.StatusOK)
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

func displaySMS(w http.ResponseWriter, r *http.Request) {
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
		writeErr(w, http.StatusBadRequest, "ERR-reset-email-01, query unescape email %v err: %v", vars["email"], err)
		return
	}

	rnd, err := genRnd(16)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "ERR-reset-email-02, RND %v err %v", email, err)
		return
	}
	forgetEmailToken := base32.StdEncoding.EncodeToString(rnd)

	err = updateEmailForgotToken(email, forgetEmailToken)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ERR-reset-email-03, update token for %v failed, token %v: %v", email, forgetEmailToken, err)
		return
	}

	url := strings.Replace(options.UrlEmail, "{email}", email, 1)
	url = strings.Replace(url, "{token}", forgetEmailToken, 1)
	url = strings.Replace(url, "{action}", "reset", 1)

	err = sendEmail(url)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ERR-reset-email-04, send email failed: %v", url)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func confirmReset(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	email, err := url.QueryUnescape(vars["email"])
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ERR-confirm-reset-email-01, query unescape email %v err: %v", vars["email"], err)
		return
	}

	token, err := url.QueryUnescape(vars["token"])
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ERR-confirm-reset-email-02, query unescape token %v err: %v", vars["token"], err)
		return
	}

	var cred Credentials
	err = json.NewDecoder(r.Body).Decode(&cred)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ERR-confirm-reset-email-03, cannot parse JSON credentials %v", err)
		return
	}

	err = validatePassword(cred.Password)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ERR-confirm-reset-email-04, password is wrong %v", err)
		return
	}

	salt, err := genRnd(16)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "ERR-confirm-reset-email-05, RND %v err %v", email, err)
		return
	}

	dk, err := scrypt.Key([]byte(cred.Password), salt, 16384, 8, 1, 32)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "ERR-confirm-reset-email-06, key %v error: %v", cred.Email, err)
		return
	}

	err = resetPassword(salt, email, dk, token)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ERR-confirm-reset-email-07, update user failed: %v", err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func setupTOTP(w http.ResponseWriter, _ *http.Request, claims *TokenClaims) {
	rnd, err := genRnd(20)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "ERR-setup-totp-01, RND %v err %v", claims.Subject, err)
		return
	}

	secret := base32.StdEncoding.EncodeToString(rnd)
	err = updateTOTP(claims.Subject, secret)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ERR-setup-totp-02, update failed %v err %v", claims.Subject, err)
		return
	}

	totp := newTOTP(secret)
	p := ProvisioningUri{}
	p.Uri = totp.ProvisioningUri(claims.Subject, options.Issuer)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(p)
}

func confirmTOTP(w http.ResponseWriter, r *http.Request, claims *TokenClaims) {
	vars := mux.Vars(r)
	token, err := url.QueryUnescape(vars["token"])
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ERR-confirm-totp-01, query unescape token %v err: %v", vars["token"], err)
		return
	}

	result, err := dbSelect(claims.Subject)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "ERR-confirm-totp-02, DB select, %v err %v", claims.Subject, err)
		return
	}

	totp := newTOTP(*result.totp)
	if token != totp.Now() {
		writeErr(w, http.StatusUnauthorized, "ERR-confirm-totp-03, token different, %v err %v", claims.Subject, err)
		return
	}
	err = updateTOTPVerified(claims.Subject)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ERR-confirm-totp-04, DB select, %v err %v", claims.Subject, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func setupSMS(w http.ResponseWriter, r *http.Request, claims *TokenClaims) {
	vars := mux.Vars(r)
	sms, err := url.QueryUnescape(vars["sms"])
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ERR-setup-sms-01, query unescape sms %v err: %v", vars["sms"], err)
		return
	}

	rnd, err := genRnd(20)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "ERR-setup-sms-02, RND %v err %v", claims.Subject, err)
		return
	}
	secret := base32.StdEncoding.EncodeToString(rnd)
	err = updateSMS(claims.Subject, secret, sms)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ERR-setup-sms-03, updateSMS failed %v err %v", claims.Subject, err)
		return
	}

	totp := newTOTP(secret)

	url := strings.Replace(options.UrlSMS, "{sms}", sms, 1)
	url = strings.Replace(url, "{token}", totp.Now(), 1)

	err = sendSMS(url)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ERR-setup-sms-04, send SMS failed %v err %v", claims.Subject, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func confirmSMS(w http.ResponseWriter, r *http.Request, claims *TokenClaims) {
	vars := mux.Vars(r)
	token, err := url.QueryUnescape(vars["token"])
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ERR-confirm-sms-01, query unescape token %v err: %v", vars["token"], err)
		return
	}

	result, err := dbSelect(claims.Subject)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "ERR-confirm-sms-02, DB select, %v err %v", claims.Subject, err)
		return
	}

	totp := newTOTP(*result.totp)
	if token != totp.Now() {
		writeErr(w, http.StatusUnauthorized, "ERR-confirm-sms-03, token different, %v err %v", claims.Subject, err)
		return
	}
	err = updateSMSVerified(claims.Subject)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ERR-confirm-sms-04, update sms failed, %v err %v", claims.Subject, err)
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

func oauth(w http.ResponseWriter, r *http.Request) {
	user, pass, ok := r.BasicAuth()
	if !ok || user != options.OAuthUser || pass != options.OAuthPass {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	grantType := r.URL.Query().Get("grant_type")
	grantType, err := url.QueryUnescape(grantType)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if grantType == "refresh_token" {
		refreshToken := r.URL.Query().Get("refresh_token")
		refreshToken, err := url.QueryUnescape(refreshToken)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if refreshToken == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		accessToken, refreshToken, expiresAt, err := refresh0(refreshToken)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Write([]byte(`{"access_token":"` + accessToken + `",
				"token_type":"Bearer",
				"refresh_token":"` + refreshToken + `",
				"expires_in":` + strconv.FormatInt(expiresAt, 10) + `}`))

	} else if grantType == "password" {
		email := r.URL.Query().Get("username")
		email, err := url.QueryUnescape(email)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		password := r.URL.Query().Get("password")
		password, err = url.QueryUnescape(password)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		scope := r.URL.Query().Get("scope")
		scope, err = url.QueryUnescape(scope)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if email == "" || password == "" || scope == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		result, err := checkEmailPassword(email, password)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "ERR-login-02 %v", err)
			return
		}

		accessToken, err := setAccessToken(string(result.role), result.id, email)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "ERR-login-11, cannot set access token for %v, %v", email, err)
			return
		}
		refreshToken, expiresAt, err := setRefreshToken(email, *result.refreshToken)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "ERR-login-12, cannot set refresh token for %v, %v", email, err)
			return
		}

		w.Write([]byte(`{"access_token":"` + accessToken + `",
				"token_type":"Bearer",
				"refresh_token":"` + refreshToken + `",
				"expires_in":` + strconv.FormatInt(expiresAt, 10) + `}`))

	} else {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

}

func liveness(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"version":"` + version + `"}`))
}

func main() {
	var opts Opts
	_, err := flags.NewParser(&opts, flags.None).Parse()
	if err != nil {
		log.Fatal(err)
	}
	f, err := os.Open("banner.txt")
	if err == nil {
		banner.Init(os.Stdout, true, false, f)
	} else {
		log.Printf("could not display banner...")
	}

	_, doneChannel := server(&opts)
	<-doneChannel
}

func loggingMiddleware(next http.Handler) http.Handler {
	return handlers.CombinedLoggingHandler(os.Stdout, next)
}

func server(opts *Opts) (*http.Server, <-chan bool) {
	options = opts

	tokenExp = time.Minute * time.Duration(opts.Expires)
	refreshExp = time.Hour * 24 * time.Duration(opts.Refresh)

	router := mux.NewRouter()
	router.Use(loggingMiddleware)
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/refresh", refresh).Methods("POST")
	router.HandleFunc("/oauth/token", oauth).Methods("POST")
	router.HandleFunc("/reset/{email}", resetEmail).Methods("POST")
	router.HandleFunc("/confirm/signup/{email}/{token}", confirmEmail).Methods("GET")
	router.HandleFunc("/confirm/reset/{email}/{token}", confirmReset).Methods("POST")

	router.HandleFunc("/setup/totp", auth(setupTOTP)).Methods("POST")
	router.HandleFunc("/confirm/totp/{token}", auth(confirmTOTP)).Methods("POST")
	router.HandleFunc("/setup/sms/{sms}", auth(setupSMS)).Methods("POST")
	router.HandleFunc("/confirm/sms/{token}", auth(confirmSMS)).Methods("POST")

	//maintenance stuff
	router.HandleFunc("/readiness", readiness).Methods("GET")
	router.HandleFunc("/liveness", liveness).Methods("GET")

	//display for debug and testing
	if options.Dev {
		router.HandleFunc("/send/email/{action}/{email}/{token}", displayEmail).Methods("GET")
		router.HandleFunc("/send/sms/{sms}/{token}", displaySMS).Methods("GET")
	}

	var err error
	db, err = initDB()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Starting auth server on port %v...", opts.Port)
	s := http.Server{
		Addr:         ":" + strconv.Itoa(opts.Port),
		Handler:      router,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	done := make(chan bool)
	go func() {
		if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
		log.Printf("Shutdown\n")
		defer db.Close()
		done <- true
	}()
	return &s, done
}

func initDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", options.DBPath+"/ffs.db")
	if err != nil {
		return nil, err
	}

	//this will create or alter tables
	//https://stackoverflow.com/questions/12518876/how-to-check-if-a-file-exists-in-go
	if _, err := os.Stat("startup.sql"); err == nil {
		file, err := ioutil.ReadFile("startup.sql")
		if err != nil {
			return nil, err
		}
		requests := strings.Split(string(file), ";")
		for _, request := range requests {
			request = strings.Replace(request, "\n", "", -1)
			request = strings.Replace(request, "\t", "", -1)
			if !strings.HasPrefix(request, "#") {
				_, err = db.Exec(request)
				if err != nil {
					return nil, fmt.Errorf("[%v] %v", request, err)
				}
			}
		}
	}

	return db, nil
}

////////// Util functions

func genRnd(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

func writeErr(w http.ResponseWriter, code int, format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	log.Printf(msg)
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(code)
	w.Write([]byte(`{"error":"` + msg + `"}`))
}

func sendEmail(url string) error {
	c := &http.Client{
		Timeout: 15 * time.Second,
	}
	resp, err := c.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("could not update DB as status from email server: %v %v", resp.Status, resp.StatusCode)
	}
	return nil
}

func sendSMS(url string) error {
	c := &http.Client{
		Timeout: 15 * time.Second,
	}
	resp, err := c.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("could not update DB as status from email server: %v %v", resp.Status, resp.StatusCode)
	}
	return nil
}

func validateEmail(email string) error {
	var rxEmail = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

	if len(email) > 254 || !rxEmail.MatchString(email) {
		return fmt.Errorf("[%s] is not a valid email address", email)
	}
	return nil
}

func validatePassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password is less than 8 characters")
	}
	return nil
}

func newTOTP(secret string) *gotp.TOTP {
	hasher := &gotp.Hasher{
		HashName: "sha256",
		Digest:   sha256.New,
	}
	return gotp.NewTOTP(secret, 6, 30, hasher)
}

func setAccessToken(role string, id []byte, subject string) (string, error) {
	tokenClaims := &TokenClaims{
		Role: role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(tokenExp).Unix(),
			Id:        base32.StdEncoding.EncodeToString(id),
			Subject:   subject,
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, tokenClaims)
	accessTokenString, err := accessToken.SignedString(jwtKey)
	if err != nil {
		return "", fmt.Errorf("JWT access token %v failed: %v", tokenClaims.Subject, err)
	}
	return accessTokenString, nil
}

func setRefreshToken(subject string, token string) (string, int64, error) {
	rc := &RefreshClaims{}
	rc.Subject = subject
	rc.ExpiresAt = time.Now().Add(refreshExp).Unix()
	rc.Token = token
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS512, rc)
	rt, err := refreshToken.SignedString(jwtKey)
	if err != nil {
		return "", 0, fmt.Errorf("JWT refresh token %v failed: %v", subject, err)
	}
	return rt, rc.ExpiresAt, nil
}
