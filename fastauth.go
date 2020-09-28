package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/dimiro1/banner"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	_ "github.com/mattn/go-sqlite3"
	ldap "github.com/vjeantet/ldapserverver"
	"github.com/xlzd/gotp"
	ed25519 "golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/scrypt"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"hash/crc64"
	"io/ioutil"
	"log"
	rnd "math/rand"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	options      *Opts
	jwtKey       []byte
	privRSA      *rsa.PrivateKey
	privRSAKid   string
	privEdDSA    *ed25519.PrivateKey
	privEdDSAKid string
	db           *sql.DB
	tokenExp     time.Duration
	refreshExp   time.Duration
)

const (
	version = "1.0.0"
)

type Opts struct {
	Dev            string
	Issuer         string
	Port           int
	Ldap           int
	DBPath         string
	UrlEmail       string
	UrlSMS         string
	Audience       string
	ExpireAccess   int
	ExpireRefresh  int
	HS256          string
	EdDSA          string
	RS256          string
	OAuthUser      string
	OAuthPass      string
	ResetRefresh   bool
	Users          string
	UserEndpoints  bool
	OauthEndpoints bool
	LdapServer     bool
	DetailedError  bool
}

func NewOpts() *Opts {
	opts := &Opts{}
	flag.StringVar(&opts.Dev, "dev", LookupEnv("DEV"), "Dev settings with initial secret")
	flag.StringVar(&opts.Issuer, "issuer", LookupEnv("ISSUER"), "name of issuer")
	flag.IntVar(&opts.Port, "port", LookupEnvInt("PORT"), "listening HTTP port")
	flag.IntVar(&opts.Port, "ldap", LookupEnvInt("LDAP"), "listening LDAP port")
	flag.StringVar(&opts.DBPath, "db-path", LookupEnv("DB_PATH"), "DB path")
	flag.StringVar(&opts.UrlEmail, "email-url", LookupEnv("EMAIL_URL"), "Email service URL")
	flag.StringVar(&opts.UrlSMS, "sms-url", LookupEnv("SMS_URL"), "SMS service URL")
	flag.StringVar(&opts.Audience, "audience", LookupEnv("SMS_URL"), "Audience")
	flag.IntVar(&opts.ExpireAccess, "expire-access", LookupEnvInt("EXPIRE_ACCESS"), "Access token expiration in seconds")
	flag.IntVar(&opts.ExpireRefresh, "expire-refresh", LookupEnvInt("EXPIRE_REFRESH"), "Refresh token expiration in seconds")
	flag.StringVar(&opts.HS256, "hs256", LookupEnv("HS256"), "HS256 key")
	flag.StringVar(&opts.RS256, "rs256", LookupEnv("RS256"), "RS256 key")
	flag.StringVar(&opts.EdDSA, "eddsa", LookupEnv("EDDSA"), "EdDSA key")
	flag.BoolVar(&opts.ResetRefresh, "reset-refresh", LookupEnv("RESET_REFRESH") != "", "Reset refresh token when setting the token")
	flag.StringVar(&opts.Users, "users", LookupEnv("USERS"), "add these initial users. E.g, -users tom@test.ch:pw123;test@test.ch:123pw")
	flag.BoolVar(&opts.UserEndpoints, "user-endpoints", LookupEnv("USER_ENDPOINTS") != "", "Enable user-facing endpoints. In dev mode these are enabled by default")
	flag.BoolVar(&opts.OauthEndpoints, "oauth-enpoints", LookupEnv("OAUTH_ENDPOINTS") != "", "Enable oauth-facing endpoints. In dev mode these are enabled by default")
	flag.BoolVar(&opts.LdapServer, "ldap-server", LookupEnv("LDAP_SERVER") != "", "Enable ldap server. In dev mode these are enabled by default")
	flag.BoolVar(&opts.DetailedError, "details", LookupEnv("DETAILS") != "", "Enable detailed errors")
	flag.Parse()
	return opts
}

func defaultOpts(opts *Opts) {

	opts.Port = setDefaultInt(opts.Port, 8080)
	opts.Ldap = setDefaultInt(opts.Ldap, 8389)
	opts.DBPath = setDefault(opts.DBPath, ".")
	opts.ExpireAccess = setDefaultInt(opts.ExpireAccess, 30*60)
	opts.ExpireRefresh = setDefaultInt(opts.ExpireRefresh, 7*24*60*60)
	opts.ResetRefresh = false

	if opts.Dev != "" {
		opts.Issuer = setDefault(opts.Issuer, "DevIssuer")
		opts.UrlEmail = setDefault(opts.UrlEmail, "http://localhost:8080/send/email/{action}/{email}/{token}")
		opts.UrlSMS = setDefault(opts.UrlSMS, "http://localhost:8080/send/sms/{sms}/{token}")
		opts.Audience = setDefault(opts.Audience, "DevAudience")
		opts.HS256 = base32.StdEncoding.EncodeToString([]byte(opts.Dev))

		h := crc64.MakeTable(0xC96C5795D7870F42)
		rsaPrivKey, err := rsa.GenerateKey(rnd.New(rnd.NewSource(int64(crc64.Checksum([]byte(opts.Dev), h)))), 2048)
		if err != nil {
			log.Fatalf("cannot generate rsa key %v", err)
		}
		encPrivRSA := x509.MarshalPKCS1PrivateKey(rsaPrivKey)
		opts.RS256 = base32.StdEncoding.EncodeToString(encPrivRSA)

		_, edPrivKey, err := ed25519.GenerateKey(rnd.New(rnd.NewSource(int64(crc64.Checksum([]byte(opts.Dev), h)))))
		if err != nil {
			log.Fatalf("cannot generate eddsa key %v", err)
		}
		opts.EdDSA = base32.StdEncoding.EncodeToString(edPrivKey)

		opts.OAuthUser = setDefault(opts.OAuthUser, "user")
		opts.OAuthPass = setDefault(opts.OAuthPass, "pass")

		opts.OauthEndpoints = true
		opts.UserEndpoints = true
		opts.LdapServer = true
		opts.DetailedError = true

		log.Printf("DEV mode active, key is %v, hex(%v)", opts.Dev, opts.HS256)
		log.Printf("DEV mode active, rsa is hex(%v)", opts.RS256)
		log.Printf("DEV mode active, eddsa is hex(%v)", opts.EdDSA)
	}

	if opts.HS256 == "" && opts.RS256 == "" && opts.EdDSA == "" {
		fmt.Printf("Paramter hs256, rs256, or eddsa not set. One of them is mandatory.\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if opts.HS256 != "" {
		var err error
		jwtKey, err = base32.StdEncoding.DecodeString(opts.HS256)
		if err != nil {
			log.Fatalf("cannot decode %v", opts.HS256)
		}
	}

	if opts.RS256 != "" {
		rsa, err := base32.StdEncoding.DecodeString(opts.RS256)
		if err != nil {
			log.Fatalf("cannot decode %v", opts.RS256)
		}
		privRSA, err = x509.ParsePKCS1PrivateKey(rsa)
		if err != nil {
			log.Fatalf("cannot decode %v", rsa)
		}
		k := jose.JSONWebKey{Key: privRSA.Public()}
		kid, err := k.Thumbprint(crypto.SHA256)
		if err != nil {
			log.Fatalf("cannot decode %v", rsa)
		}
		privRSAKid = hex.EncodeToString(kid)
	}

	if opts.EdDSA != "" {
		eddsa, err := base32.StdEncoding.DecodeString(opts.EdDSA)
		if err != nil {
			log.Fatalf("cannot decode %v", opts.EdDSA)
		}
		privEdDSA0 := ed25519.PrivateKey(eddsa)
		privEdDSA = &privEdDSA0
		k := jose.JSONWebKey{Key: privEdDSA.Public()}
		kid, err := k.Thumbprint(crypto.SHA256)
		if err != nil {
			log.Fatalf("cannot decode %v", opts.EdDSA)
		}
		privEdDSAKid = hex.EncodeToString(kid)
	}
}

func setDefaultInt(actualValue int, defaultValue int) int {
	if actualValue == 0 {
		return defaultValue
	}
	return actualValue
}

func setDefault(actualValue string, defaultValue string) string {
	if actualValue == "" {
		return defaultValue
	}
	return actualValue
}

func LookupEnv(key string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return ""
}

func LookupEnvInt(key string) int {
	if val, ok := os.LookupEnv(key); ok {
		v, err := strconv.Atoi(val)
		if err != nil {
			log.Printf("LookupEnvOrInt[%s]: %v", key, err)
			return 0
		}
		return v
	}
	return 0
}

type Credentials struct {
	Email    string `json:"email,omitempty"`
	Password string `json:"password"`
	TOTP     string `json:"totp,omitempty"`
}

type TokenClaims struct {
	Role string `json:"role,omitempty"`
	jwt.Claims
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

func basicAuth(next func(w http.ResponseWriter, r *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if options.OAuthUser != "" || options.OAuthPass != "" {
			user, pass, ok := r.BasicAuth()
			if !ok || user != options.OAuthUser || pass != options.OAuthPass {
				writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-basic-auth-01, could not check user/pass: %v", user)
				return
			}
		}
		next(w, r)
	}
}

func jwtAuth(next func(w http.ResponseWriter, r *http.Request, claims *TokenClaims)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		authorizationHeader := r.Header.Get("Authorization")
		if authorizationHeader != "" {
			bearerToken := strings.Split(authorizationHeader, " ")
			if len(bearerToken) == 2 {

				tok, err := jwt.ParseSigned(bearerToken[1])
				if err != nil {
					writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-auth-01, could not parse token: %v", bearerToken[1])
					return
				}

				claims := &TokenClaims{}

				if tok.Headers[0].Algorithm == string(jose.RS256) {
					err = tok.Claims(privRSA.Public(), claims)
				} else if tok.Headers[0].Algorithm == string(jose.HS256) {
					err = tok.Claims(jwtKey, claims)
				} else if tok.Headers[0].Algorithm == string(jose.EdDSA) {
					err = tok.Claims(privEdDSA.Public(), claims)
				}

				if err != nil {
					writeErr(w, http.StatusUnauthorized, "invalid_client", true, "ERR-auth-02, could not parse claims: %v", bearerToken[1])
					return
				}

				if !claims.Expiry.Time().After(time.Now()) {
					writeErr(w, http.StatusBadRequest, "invalid_client", false, "ERR-auth-03, expired: %v", bearerToken[1])
					return
				}

				next(w, r, claims)
				return
			} else {
				writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-auth-04, could not split token: %v", bearerToken[1])
				return
			}
		}
		writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-auth-05, authorization header not set")
		return
	}
}

func refresh(w http.ResponseWriter, r *http.Request) {
	//https://medium.com/monstar-lab-bangladesh-engineering/jwt-auth-in-go-part-2-refresh-tokens-d334777ca8a0

	//check if refresh token matches
	c, err := r.Cookie("refresh")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-refresh-01, cookie not found: %v", err)
		return
	}
	accessToken, refreshToken, expiresAt, err := refresh0(c.Value)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid_request", false, "ERR-refresh-02 %v", err)
		return
	}
	w.Header().Set("Token", accessToken)

	cookie := http.Cookie{
		Name:     "refresh",
		Value:    refreshToken,
		Path:     "/refresh",
		HttpOnly: true,
		Secure:   options.Dev == "",
		Expires:  time.Unix(expiresAt, 0),
	}
	w.Header().Set("Set-Cookie", cookie.String())
	w.WriteHeader(http.StatusOK)
}
func refresh0(token string) (string, string, int64, error) {

	tok, err := jwt.ParseSigned(token)
	if err != nil {
		return "", "", 0, fmt.Errorf("ERR-refresh-01, could not check sig %v", err)
	}

	refreshClaims := &RefreshClaims{}
	if tok.Headers[0].Algorithm == string(jose.RS256) {
		err = tok.Claims(privRSA.Public(), refreshClaims)
		if err != nil {
			return "", "", 0, fmt.Errorf("ERR-refresh-02, could not parse claims %v", err)
		}
	}
	if tok.Headers[0].Algorithm == string(jose.HS256) {
		err = tok.Claims(jwtKey, refreshClaims)
		if err != nil {
			return "", "", 0, fmt.Errorf("ERR-refresh-02, could not parse claims %v", err)
		}
	}
	if tok.Headers[0].Algorithm == string(jose.EdDSA) {
		err = tok.Claims(privEdDSA.Public(), refreshClaims)
		if err != nil {
			return "", "", 0, fmt.Errorf("ERR-refresh-02, could not parse claims %v", err)
		}
	}

	t := time.Unix(refreshClaims.ExpiresAt, 0)
	if !t.After(time.Now()) {
		return "", "", 0, fmt.Errorf("ERR-refresh-03, expired %v", err)
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

	accessTokenString, err := setAccessToken(string(result.role), refreshClaims.Subject)
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
		writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-confirm-email-01, update email token for %v failed, token %v: %v", email, token, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func signup(w http.ResponseWriter, r *http.Request) {
	var cred Credentials
	err := json.NewDecoder(r.Body).Decode(&cred)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-signup-01, cannot parse JSON credentials %v", err)
		return
	}

	err = validateEmail(cred.Email)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-signup-02, email is wrong %v", err)
		return
	}

	err = validatePassword(cred.Password)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-signup-03, password is wrong %v", err)
		return
	}

	rnd, err := genRnd(48)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-signup-04, RND %v err %v", cred.Email, err)
		return
	}
	emailToken := base32.StdEncoding.EncodeToString(rnd[0:16])

	//https://security.stackexchange.com/questions/11221/how-big-should-salt-be

	salt := rnd[16:32]
	dk, err := scrypt.Key([]byte(cred.Password), salt, 16384, 8, 1, 32)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-signup-05, key %v error: %v", cred.Email, err)
		return
	}

	refreshToken := base32.StdEncoding.EncodeToString(rnd[32:48])

	err = insertUser(salt, cred.Email, dk, emailToken, refreshToken)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-signup-06, insert user failed: %v", err)
		return
	}

	url := strings.Replace(options.UrlEmail, "{email}", url.QueryEscape(cred.Email), 1)
	url = strings.Replace(url, "{token}", emailToken, 1)
	url = strings.Replace(url, "{action}", "signup", 1)

	err = sendEmail(url)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-signup-07, send email failed: %v", url)
		return
	}

	err = updateMailStatus(cred.Email)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-signup-08, db update failed: %v", err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func checkEmailPassword(email string, password string) (*dbRes, bool, error) {
	result, err := dbSelect(email)
	if err != nil {
		return nil, false, fmt.Errorf("ERR-checkEmail-01, DB select, %v err %v", email, err)
	}

	if result.emailVerified == nil || result.emailVerified.Unix() == 0 {
		return nil, false, fmt.Errorf("ERR-checkEmail-02, user %v no email verified: %v", email, err)
	}

	if *result.errorCount > 2 {
		return nil, false, fmt.Errorf("ERR-checkEmail-03, user %v no email verified: %v", email, err)
	}

	dk, err := scrypt.Key([]byte(password), result.salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, false, fmt.Errorf("ERR-checkEmail-04, key %v error: %v", email, err)
	}

	if bytes.Compare(dk, result.password) != 0 {
		err = incErrorCount(email)
		if err != nil {
			return nil, false, fmt.Errorf("ERR-checkEmail-05, key %v error: %v", email, err)
		}
		return nil, true, fmt.Errorf("ERR-checkEmail-06, user %v password mismatch", email)
	}
	err = resetCount(email)
	if err != nil {
		return nil, false, fmt.Errorf("ERR-checkEmail-05, key %v error: %v", email, err)
	}
	return result, false, nil
}

func login(w http.ResponseWriter, r *http.Request) {
	var cred Credentials
	err := json.NewDecoder(r.Body).Decode(&cred)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-login-01, cannot parse JSON credentials %v", err)
		return
	}

	result, retryPossible, err := checkEmailPassword(cred.Email, cred.Password)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_client", retryPossible, "ERR-login-02 %v", err)
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
				writeErr(w, http.StatusUnauthorized, "invalid_request", false, "ERR-login-07, send sms failed %v error: %v", cred.Email, err)
				return
			}
			writeErr(w, http.StatusTeapot, "invalid_client", true, "ERR-login-08, waiting for sms verification: %v", cred.Email)
			return
		} else if token != cred.TOTP {
			writeErr(w, http.StatusForbidden, "invalid_request", false, "ERR-login-09, sms wrong token, %v err %v", cred.Email, err)
			return
		}
	}

	//TOTP logic
	if result.totp != nil && result.totpVerified != nil {
		totp := newTOTP(*result.totp)
		token := totp.Now()
		if token != cred.TOTP {
			writeErr(w, http.StatusForbidden, "invalid_request", false, "ERR-login-10, totp wrong token, %v err %v", cred.Email, err)
			return
		}
	}

	accessToken, err := setAccessToken(string(result.role), cred.Email)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "invalid_request", false, "ERR-login-11, cannot set access token for %v, %v", cred.Email, err)
		return
	}
	refreshToken, expiresAt, err := setRefreshToken(cred.Email, *result.refreshToken)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "invalid_request", false, "ERR-login-13, cannot set refresh token for %v, %v", cred.Email, err)
		return
	}

	w.Header().Set("Token", accessToken)

	cookie := http.Cookie{
		Name:     "refresh",
		Value:    refreshToken,
		Path:     "/refresh",
		HttpOnly: true,
		Secure:   options.Dev == "",
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
		writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-reset-email-01, query unescape email %v err: %v", vars["email"], err)
		return
	}

	rnd, err := genRnd(16)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-reset-email-02, RND %v err %v", email, err)
		return
	}
	forgetEmailToken := base32.StdEncoding.EncodeToString(rnd)

	err = updateEmailForgotToken(email, forgetEmailToken)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-reset-email-03, update token for %v failed, token %v: %v", email, forgetEmailToken, err)
		return
	}

	url := strings.Replace(options.UrlEmail, "{email}", email, 1)
	url = strings.Replace(url, "{token}", forgetEmailToken, 1)
	url = strings.Replace(url, "{action}", "reset", 1)

	err = sendEmail(url)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-reset-email-04, send email failed: %v", url)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func confirmReset(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	email, err := url.QueryUnescape(vars["email"])
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-confirm-reset-email-01, query unescape email %v err: %v", vars["email"], err)
		return
	}

	token, err := url.QueryUnescape(vars["token"])
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-confirm-reset-email-02, query unescape token %v err: %v", vars["token"], err)
		return
	}

	var cred Credentials
	err = json.NewDecoder(r.Body).Decode(&cred)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-confirm-reset-email-03, cannot parse JSON credentials %v", err)
		return
	}

	err = validatePassword(cred.Password)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-confirm-reset-email-04, password is wrong %v", err)
		return
	}

	salt, err := genRnd(16)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-confirm-reset-email-05, RND %v err %v", email, err)
		return
	}

	dk, err := scrypt.Key([]byte(cred.Password), salt, 16384, 8, 1, 32)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid_request", false, "ERR-confirm-reset-email-06, key %v error: %v", cred.Email, err)
		return
	}

	err = resetPassword(salt, email, dk, token)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-confirm-reset-email-07, update user failed: %v", err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func setupTOTP(w http.ResponseWriter, _ *http.Request, claims *TokenClaims) {
	rnd, err := genRnd(20)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-setup-totp-01, RND %v err %v", claims.Subject, err)
		return
	}

	secret := base32.StdEncoding.EncodeToString(rnd)
	err = updateTOTP(claims.Subject, secret)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-setup-totp-02, update failed %v err %v", claims.Subject, err)
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
		writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-confirm-totp-01, query unescape token %v err: %v", vars["token"], err)
		return
	}

	result, err := dbSelect(claims.Subject)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-confirm-totp-02, DB select, %v err %v", claims.Subject, err)
		return
	}

	totp := newTOTP(*result.totp)
	if token != totp.Now() {
		writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-confirm-totp-03, token different, %v err %v", claims.Subject, err)
		return
	}
	err = updateTOTPVerified(claims.Subject)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-confirm-totp-04, DB select, %v err %v", claims.Subject, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func setupSMS(w http.ResponseWriter, r *http.Request, claims *TokenClaims) {
	vars := mux.Vars(r)
	sms, err := url.QueryUnescape(vars["sms"])
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-setup-sms-01, query unescape sms %v err: %v", vars["sms"], err)
		return
	}

	rnd, err := genRnd(20)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-setup-sms-02, RND %v err %v", claims.Subject, err)
		return
	}
	secret := base32.StdEncoding.EncodeToString(rnd)
	err = updateSMS(claims.Subject, secret, sms)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-setup-sms-03, updateSMS failed %v err %v", claims.Subject, err)
		return
	}

	totp := newTOTP(secret)

	url := strings.Replace(options.UrlSMS, "{sms}", sms, 1)
	url = strings.Replace(url, "{token}", totp.Now(), 1)

	err = sendSMS(url)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-setup-sms-04, send SMS failed %v err %v", claims.Subject, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func confirmSMS(w http.ResponseWriter, r *http.Request, claims *TokenClaims) {
	vars := mux.Vars(r)
	token, err := url.QueryUnescape(vars["token"])
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-confirm-sms-01, query unescape token %v err: %v", vars["token"], err)
		return
	}

	result, err := dbSelect(claims.Subject)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-confirm-sms-02, DB select, %v err %v", claims.Subject, err)
		return
	}

	totp := newTOTP(*result.totp)
	if token != totp.Now() {
		writeErr(w, http.StatusUnauthorized, "invalid_request", false, "ERR-confirm-sms-03, token different, %v err %v", claims.Subject, err)
		return
	}
	err = updateSMSVerified(claims.Subject)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-confirm-sms-04, update sms failed, %v err %v", claims.Subject, err)
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

func param(name string, r *http.Request) string {

	n1 := mux.Vars(r)[name]
	n2, _ := url.QueryUnescape(r.URL.Query().Get(name))
	n3 := r.FormValue(name)

	if n1 == "" {
		if n2 == "" {
			return n3
		}
		return n2
	}
	return n1
}

func oauth(w http.ResponseWriter, r *http.Request) {

	grantType := param("grant_type", r)
	if grantType == "refresh_token" {
		refreshToken := param("refresh_token", r)
		if refreshToken == "" {
			writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-oauth-01, no refresh token")
			return
		}

		accessToken, refreshToken, expiresAt, err := refresh0(refreshToken)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_grant", false, "ERR-oauth-02, cannot verify refresh token %v", err)
			return
		}
		w.Write([]byte(`{"access_token":"` + accessToken + `",
				"token_type":"Bearer",
				"refresh_token":"` + refreshToken + `",
				"expires_in":` + strconv.FormatInt(expiresAt, 10) + `}`))

	} else if grantType == "password" {
		email := param("username", r)
		password := param("password", r)
		scope := param("scope", r)
		if email == "" || password == "" || scope == "" {
			writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-oauth-03, username, password, or scope empty")
			return
		}

		result, retryPossible, err := checkEmailPassword(email, password)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_grant", retryPossible, "ERR-oauth-04 %v", err)
			return
		}

		accessToken, err := setAccessToken(string(result.role), email)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-oauth-05, cannot set access token for %v, %v", email, err)
			return
		}
		refreshToken, expiresAt, err := setRefreshToken(email, *result.refreshToken)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-oauth-06, cannot set refresh token for %v, %v", email, err)
			return
		}

		w.Write([]byte(`{"access_token":"` + accessToken + `",
				"token_type":"Bearer",
				"refresh_token":"` + refreshToken + `",
				"expires_in":` + strconv.FormatInt(expiresAt, 10) + `}`))

	} else {
		writeErr(w, http.StatusBadRequest, "unsupported_grant_type", false, "ERR-oauth-07, unsupported grant type")
		return
	}
}

func liveness(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"version":"` + version + `"}`))
}

func jwkFunc(w http.ResponseWriter, r *http.Request) {

	json := []byte(`{"keys":[`)
	if privRSA != nil {
		k := jose.JSONWebKey{Key: privRSA.Public()}
		kid, err := k.Thumbprint(crypto.SHA256)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-jwk-1, %v", err)
			return
		}
		k.KeyID = hex.EncodeToString(kid)
		mj, err := k.MarshalJSON()
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-jwk-2, %v", err)
			return
		}
		json = append(json, mj...)
	}
	if privEdDSA != nil {
		k := jose.JSONWebKey{Key: privEdDSA.Public()}
		mj, err := k.MarshalJSON()
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", false, "ERR-jwk-3, %v", err)
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

func main() {
	f, err := os.Open("banner.txt")
	if err == nil {
		banner.Init(os.Stdout, true, false, f)
	} else {
		log.Printf("could not display banner...")
	}

	o := NewOpts()
	defaultOpts(o)
	options = o

	db, err = initDB()
	if err != nil {
		log.Fatal(err)
	}
	setupDB()
	serverRest, doneChannelRest := serverRest()
	serverLdap, doneChannelLdap := serverLdap()

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		serverRest.Shutdown(context.Background())
		serverLdap.Stop()
		if serverLdap.Listener != nil {
			serverLdap.Listener.Close()
		}
	}()

	<-doneChannelRest
	<-doneChannelLdap
	db.Close()
}

func mainTest(opts *Opts) func() {
	defaultOpts(opts)
	options = opts
	var err error
	db, err = initDB()
	if err != nil {
		log.Fatal(err)
	}
	setupDB()
	serverRest, doneChannelRest := serverRest()
	serverLdap, doneChannelLdap := serverLdap()

	return func() {
		serverRest.Shutdown(context.Background())
		serverLdap.Stop()
		if serverLdap.Listener != nil {
			serverLdap.Listener.Close()
		}
		<-doneChannelRest
		<-doneChannelLdap
		db.Close()
	}
}

func loggingMiddleware(next http.Handler) http.Handler {
	return handlers.CombinedLoggingHandler(os.Stdout, next)
}

func addInitialUser(username string, password string) error {
	res, err := dbSelect(username)
	if res == nil || err != nil {
		salt := []byte{0}
		dk, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, 32)
		if err != nil {
			return err
		}
		err = insertUser(salt, username, dk, "emailToken", "refreshToken")
		if err != nil {
			return err
		}
		err = updateEmailToken(username, "emailToken")
		if err != nil {
			return err
		}
	}
	return nil
}

func serverLdap() (*ldap.Server, <-chan bool) {
	routes := ldap.NewRouteMux()
	routes.Bind(handleBind)

	server := ldap.NewServer()
	server.Handle(routes)

	done := make(chan bool)
	if options.LdapServer {
		go func(s *ldap.Server) {
			addr := ":" + strconv.Itoa(options.Ldap)
			log.Printf("Starting auth server on port %v...", addr)
			err := s.ListenAndServe(addr)
			log.Printf("server closed %v", err)
			done <- true
		}(server)
	} else {
		done <- true
	}

	return server, done
}

func handleBind(w ldap.ResponseWriter, m *ldap.Message) {
	r := m.GetBindRequest()

	_, retryPossible, err := checkEmailPassword(string(r.Name()), string(r.AuthenticationSimple()))
	if err != nil {
		res := ldap.NewBindResponse(ldap.LDAPResultInvalidCredentials)
		if options.DetailedError {
			if retryPossible {
				res.SetDiagnosticMessage(fmt.Sprintf("invalid credentials for %v, please retry", string(r.Name())))
			} else {
				res.SetDiagnosticMessage(fmt.Sprintf("invalid credentials for %v", string(r.Name())))
			}
		}
		w.Write(res)
		return
	}

	res := ldap.NewBindResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func setupDB() {
	if options.Users != "" {
		//add user for development
		users := strings.Split(options.Users, ";")
		for _, user := range users {
			userpw := strings.Split(user, ":")
			if len(userpw) == 2 {
				err := addInitialUser(userpw[0], userpw[1])
				if err == nil {
					log.Printf("insterted user %v", userpw[0])
				} else {
					log.Printf("could not insert %v", userpw[0])
				}
			} else {
				log.Printf("username and password need to be seperated by ':'")
			}
		}
	}
}

func serverRest() (*http.Server, <-chan bool) {
	tokenExp = time.Second * time.Duration(options.ExpireAccess)
	refreshExp = time.Second * time.Duration(options.ExpireRefresh)

	router := mux.NewRouter()
	router.Use(loggingMiddleware)

	if options.UserEndpoints {
		router.HandleFunc("/login", login).Methods("POST")
		router.HandleFunc("/signup", signup).Methods("POST")
		router.HandleFunc("/refresh", refresh).Methods("POST")
		router.HandleFunc("/reset/{email}", resetEmail).Methods("POST")
		router.HandleFunc("/confirm/signup/{email}/{token}", confirmEmail).Methods("GET")
		router.HandleFunc("/confirm/reset/{email}/{token}", confirmReset).Methods("POST")

		router.HandleFunc("/setup/totp", jwtAuth(setupTOTP)).Methods("POST")
		router.HandleFunc("/confirm/totp/{token}", jwtAuth(confirmTOTP)).Methods("POST")
		router.HandleFunc("/setup/sms/{sms}", jwtAuth(setupSMS)).Methods("POST")
		router.HandleFunc("/confirm/sms/{token}", jwtAuth(confirmSMS)).Methods("POST")
	}

	//maintenance stuff
	router.HandleFunc("/readiness", readiness).Methods("GET")
	router.HandleFunc("/liveness", liveness).Methods("GET")

	//display for debug and testing
	if options.Dev != "" {
		router.HandleFunc("/send/email/{action}/{email}/{token}", displayEmail).Methods("GET")
		router.HandleFunc("/send/sms/{sms}/{token}", displaySMS).Methods("GET")
	}

	if options.OauthEndpoints {
		router.HandleFunc("/oauth/token", basicAuth(oauth)).Methods("POST")
		router.HandleFunc("/oauth/.well-known/jwks.json", jwkFunc).Methods("GET")
	}

	s := &http.Server{
		Addr:         ":" + strconv.Itoa(options.Port),
		Handler:      limit(router),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	done := make(chan bool)
	go func(s *http.Server) {
		log.Printf("Starting auth server on port %v...", s.Addr)
		s.ListenAndServe()
		if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
		log.Printf("Shutdown\n")
		done <- true
	}(s)
	return s, done
}

func initDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", options.DBPath+"/fastauth.db")
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

func writeErr(w http.ResponseWriter, code int, error string, retryPossible bool, format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	log.Printf(msg)
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(code)
	if options.DetailedError {
		msg = `,"error_message":"` + msg + `"`
	} else {
		msg = ""
	}
	if retryPossible {
		w.Write([]byte(`{"error":"` + error + `","error_uri":"https://host:port/error-descriptions/authorization-request/invalid_request/refused"` + msg + `}`))
	} else {
		w.Write([]byte(`{"error":"` + error + `","error_uri":"https://host:port/error-descriptions/authorization-request/invalid_request/blocked"` + msg + `}`))
	}
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

func setAccessToken(role string, subject string) (string, error) {
	tokenClaims := &TokenClaims{
		Role: role,
		Claims: jwt.Claims{
			Expiry:  jwt.NewNumericDate(time.Now().Add(tokenExp)),
			Subject: subject,
		},
	}
	var sig jose.Signer
	var err error
	if options.RS256 != "" {
		sig, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privRSA}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", privRSAKid))
	} else if options.EdDSA != "" {
		sig, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: privEdDSA}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", privEdDSAKid))
	} else {
		sig, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: jwtKey}, (&jose.SignerOptions{}).WithType("JWT"))
	}

	if err != nil {
		return "", fmt.Errorf("JWT access token %v failed: %v", tokenClaims.Subject, err)
	}
	accessTokenString, err := jwt.Signed(sig).Claims(tokenClaims).CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("JWT access token %v failed: %v", tokenClaims.Subject, err)
	}
	fmt.Printf("[%s]", accessTokenString)
	return accessTokenString, nil
}

func setRefreshToken(subject string, token string) (string, int64, error) {

	if options.ResetRefresh {
		rnd, err := genRnd(16)
		if err != nil {
			return "", 0, fmt.Errorf("JWT refresh token %v failed: %v", subject, err)
		}
		token = base32.StdEncoding.EncodeToString(rnd)
		resetRefreshToken(subject, token)
	}

	rc := &RefreshClaims{}
	rc.Subject = subject
	rc.ExpiresAt = time.Now().Add(refreshExp).Unix()
	rc.Token = token

	var sig jose.Signer
	var err error
	if options.RS256 != "" {
		sig, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privRSA}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", privRSAKid))
	} else if options.EdDSA != "" {
		sig, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: privEdDSA}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", privEdDSAKid))
	} else {
		sig, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: jwtKey}, (&jose.SignerOptions{}).WithType("JWT"))
	}

	if err != nil {
		return "", 0, fmt.Errorf("JWT refresh token %v failed: %v", subject, err)
	}
	refreshToken, err := jwt.Signed(sig).Claims(rc).CompactSerialize()
	if err != nil {
		return "", 0, fmt.Errorf("JWT refresh token %v failed: %v", subject, err)
	}
	fmt.Printf("[%s]", refreshToken)
	return refreshToken, rc.ExpiresAt, nil
}
