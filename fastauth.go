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
	"github.com/gorilla/schema"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	ldap "github.com/vjeantet/ldapserver"
	"github.com/xlzd/gotp"
	ed25519 "golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/scrypt"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"hash/crc64"
	"io/ioutil"
	"log"
	rnd "math/rand"
	"net"
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
	codeExp      time.Duration
)

const (
	version = "1.0.0"
)

type Opts struct {
	Env            string
	Dev            string
	Issuer         string
	Port           int
	Ldap           int
	DBPath         string
	DBDriver       string
	UrlEmail       string
	UrlSMS         string
	Audience       string
	ExpireAccess   int
	ExpireRefresh  int
	ExpireCode     int
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
	Redirects      string
	PasswordFlow   bool
	Scope          string
}

func NewOpts() *Opts {
	opts := &Opts{}
	flag.StringVar(&opts.Dev, "dev", LookupEnv("DEV"), "Dev settings with initial secret")
	flag.StringVar(&opts.Issuer, "issuer", LookupEnv("ISSUER"), "name of issuer, default in dev is my-issuer")
	flag.IntVar(&opts.Port, "port", LookupEnvInt("PORT"), "listening HTTP port")
	flag.IntVar(&opts.Ldap, "ldap", LookupEnvInt("LDAP"), "listening LDAP port")
	flag.StringVar(&opts.DBPath, "db-path", LookupEnv("DB_PATH"), "DB path")
	flag.StringVar(&opts.DBDriver, "db-driver", LookupEnv("DB_DRIVER"), "DB driver")
	flag.StringVar(&opts.UrlEmail, "email-url", LookupEnv("EMAIL_URL"), "Email service URL")
	flag.StringVar(&opts.UrlSMS, "sms-url", LookupEnv("SMS_URL"), "SMS service URL")
	flag.StringVar(&opts.Audience, "audience", LookupEnv("AUDIENCE"), "Audience, default in dev is my-audience")
	flag.IntVar(&opts.ExpireAccess, "expire-access", LookupEnvInt("EXPIRE_ACCESS"), "Access token expiration in seconds")
	flag.IntVar(&opts.ExpireRefresh, "expire-refresh", LookupEnvInt("EXPIRE_REFRESH"), "Refresh token expiration in seconds")
	flag.IntVar(&opts.ExpireCode, "expire-code", LookupEnvInt("EXPIRE_CODE"), "Authtoken flow expiration in seconds")
	flag.StringVar(&opts.HS256, "hs256", LookupEnv("HS256"), "HS256 key")
	flag.StringVar(&opts.RS256, "rs256", LookupEnv("RS256"), "RS256 key")
	flag.StringVar(&opts.EdDSA, "eddsa", LookupEnv("EDDSA"), "EdDSA key")
	flag.BoolVar(&opts.ResetRefresh, "reset-refresh", LookupEnv("RESET_REFRESH") != "", "Reset refresh token when setting the token")
	flag.StringVar(&opts.Users, "users", LookupEnv("USERS"), "add these initial users. E.g, -users tom@test.ch:pw123;test@test.ch:123pw")
	flag.BoolVar(&opts.UserEndpoints, "user-endpoints", LookupEnv("USER_ENDPOINTS") != "", "Enable user-facing endpoints. In dev mode these are enabled by default")
	flag.BoolVar(&opts.OauthEndpoints, "oauth-enpoints", LookupEnv("OAUTH_ENDPOINTS") != "", "Enable oauth-facing endpoints. In dev mode these are enabled by default")
	flag.BoolVar(&opts.LdapServer, "ldap-server", LookupEnv("LDAP_SERVER") != "", "Enable ldap server. In dev mode these are enabled by default")
	flag.BoolVar(&opts.DetailedError, "details", LookupEnv("DETAILS") != "", "Enable detailed errors")
	flag.StringVar(&opts.Redirects, "redir", LookupEnv("REDIR"), "add client redirects. E.g, -redir clientId1:http://blabla;clientId2:http://blublu")
	flag.BoolVar(&opts.PasswordFlow, "pwflow", LookupEnv("PWFLOW") != "", "enable password flow, default disabled")
	flag.StringVar(&opts.Scope, "scope", LookupEnv("SCOPE"), "scope, default in dev is my-scope")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()
	return opts
}

func defaultOpts(opts *Opts) {
	if opts.Env == "local" {
		err := godotenv.Load()
		if err != nil {
			err = godotenv.Load("../.env")
			if err != nil {
				log.Printf("could not find env file in this or in the parent dir: %v", err)
			}
		}
	}

	opts.Port = setDefaultInt(opts.Port, LookupEnvInt("PORT"), 8080)
	opts.Ldap = setDefaultInt(opts.Ldap, LookupEnvInt("LDAP"), 8389)
	opts.DBPath = setDefault(opts.DBPath, LookupEnv("DB_PATH"), "./fastauth.db")
	opts.DBDriver = setDefault(opts.DBDriver, LookupEnv("DB_DRIVER"), "sqlite3")
	opts.ExpireAccess = setDefaultInt(opts.ExpireAccess, LookupEnvInt("EXPIRE_ACCESS"), 30*60)         //30min
	opts.ExpireRefresh = setDefaultInt(opts.ExpireRefresh, LookupEnvInt("EXPIRE_REFRESH"), 7*24*60*60) //7days
	opts.ExpireCode = setDefaultInt(opts.ExpireCode, LookupEnvInt("EXPIRE_CODE"), 60)                  //1min
	opts.ResetRefresh = setDefaultBool(opts.ResetRefresh, LookupEnv("RESET_REFRESH") != "", false)
	opts.PasswordFlow = setDefaultBool(opts.PasswordFlow, LookupEnv("PWFLOW") != "", false)

	opts.HS256 = setDefault(opts.HS256, LookupEnv("HS256"))
	opts.RS256 = setDefault(opts.RS256, LookupEnv("RS256"))
	opts.EdDSA = setDefault(opts.EdDSA, LookupEnv("EDDSA"))

	if opts.Dev != "" {
		opts.Scope = setDefault(opts.Scope, LookupEnv("SCOPE"), "my-scope")
		opts.Audience = setDefault(opts.Audience, LookupEnv("AUDIENCE"), "my-audience")
		opts.Issuer = setDefault(opts.Issuer, LookupEnv("ISSUER"), "my-issuer")
		opts.UrlEmail = setDefault(opts.UrlEmail, LookupEnv("EMAIL_URL"), "http://localhost:8080/send/email/{action}/{email}/{token}")
		opts.UrlSMS = setDefault(opts.UrlSMS, LookupEnv("SMS_URL"), "http://localhost:8080/send/sms/{sms}/{token}")
		dev := setDefault(opts.Dev, LookupEnv("DEV"), opts.Dev)
		if strings.ToLower(opts.HS256) != "false" {
			opts.HS256 = base32.StdEncoding.EncodeToString([]byte(dev))
		}
		h := crc64.MakeTable(0xC96C5795D7870F42)
		if strings.ToLower(opts.RS256) != "false" {
			rsaPrivKey, err := rsa.GenerateKey(rnd.New(rnd.NewSource(int64(crc64.Checksum([]byte(dev), h)))), 2048)
			if err != nil {
				log.Fatalf("cannot generate rsa key %v", err)
			}
			encPrivRSA, err := x509.MarshalPKCS8PrivateKey(rsaPrivKey)
			if err != nil {
				log.Fatalf("cannot generate rsa key %v", err)
			}
			opts.RS256 = base32.StdEncoding.EncodeToString(encPrivRSA)
		}
		if strings.ToLower(opts.EdDSA) != "false" {
			_, edPrivKey, err := ed25519.GenerateKey(rnd.New(rnd.NewSource(int64(crc64.Checksum([]byte(dev), h)))))
			if err != nil {
				log.Fatalf("cannot generate eddsa key %v", err)
			}
			opts.EdDSA = base32.StdEncoding.EncodeToString(edPrivKey)
		}
		opts.OauthEndpoints = true
		opts.UserEndpoints = true
		opts.LdapServer = true
		opts.DetailedError = true
		opts.PasswordFlow = true

		if opts.Users == "" {
			opts.Users = "user:pass"
		}

		log.Printf("DEV mode active, key is %v, hex(%v)", opts.Dev, opts.HS256)
		log.Printf("DEV mode active, rsa is hex(%v)", opts.RS256)
		log.Printf("DEV mode active, eddsa is hex(%v)", opts.EdDSA)
	}

	if (opts.HS256 == "" || strings.ToLower(opts.HS256) == "false") &&
		(opts.RS256 == "" || strings.ToLower(opts.RS256) == "false") &&
		(opts.EdDSA == "" || strings.ToLower(opts.EdDSA) == "false") {
		fmt.Printf("Paramter hs256, rs256, or eddsa not set. One of them is mandatory.\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if opts.HS256 != "" && strings.ToLower(opts.HS256) != "false" {
		var err error
		jwtKey, err = base32.StdEncoding.DecodeString(opts.HS256)
		if err != nil {
			log.Fatalf("cannot decode %v", opts.HS256)
		}
	}

	if opts.RS256 != "" && strings.ToLower(opts.RS256) != "false" {
		rsaDec, err := base32.StdEncoding.DecodeString(opts.RS256)
		if err != nil {
			log.Fatalf("cannot decode %v", opts.RS256)
		}
		i, err := x509.ParsePKCS8PrivateKey(rsaDec)
		privRSA = i.(*rsa.PrivateKey)
		if err != nil {
			log.Fatalf("cannot decode %v", rsaDec)
		}
		k := jose.JSONWebKey{Key: privRSA.Public()}
		kid, err := k.Thumbprint(crypto.SHA256)
		if err != nil {
			log.Fatalf("cannot decode %v", rsaDec)
		}
		privRSAKid = hex.EncodeToString(kid)
	}

	if opts.EdDSA != "" && strings.ToLower(opts.EdDSA) != "false" {
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

func setDefault(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func setDefaultInt(values ...int) int {
	for _, v := range values {
		if v != 0 {
			return v
		}
	}
	return 0
}

func setDefaultBool(values ...bool) bool {
	for _, v := range values {
		if v {
			return v
		}
	}
	return false
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
	Email    string `json:"email,omitempty" schema:"email"`
	Password string `json:"password" schema:"password,required"`
	TOTP     string `json:"totp,omitempty" schema:"totp"`
	//here comes oauth, leave empty on regular login
	//If you want to use oauth, you need to configure
	//client-id with a matching redirect-uri from the
	//command line
	ClientId                string `json:"client_id,omitempty" schema:"client_id"`
	ResponseType            string `json:"response_type,omitempty" schema:"response_type"`
	State                   string `json:"state,omitempty" schema:"state"`
	Scope                   string `json:"scope" schema:"scope"`
	RedirectUri             string `json:"redirect_uri,omitempty" schema:"redirect_uri"`
	CodeChallenge           string `json:"code_challenge,omitempty" schema:"code_challenge"`
	CodeCodeChallengeMethod string `json:"code_challenge_method,omitempty" schema:"code_challenge_method"`
}

type TokenClaims struct {
	Role     string `json:"role,omitempty"`
	Scope    string `json:"scope,omitempty"`
	ClientID string `json:"client_id,omitempty"`
	jwt.Claims
}
type RefreshClaims struct {
	ExpiresAt int64  `json:"exp,omitempty"`
	Subject   string `json:"role,omitempty"`
	Token     string `json:"token,omitempty"`
}
type CodeClaims struct {
	ExpiresAt               int64  `json:"exp,omitempty"`
	Subject                 string `json:"role,omitempty"`
	CodeChallenge           string `json:"code_challenge,omitempty"`
	CodeCodeChallengeMethod string `json:"code_challenge_method,omitempty"`
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

func jwtAuth(next func(w http.ResponseWriter, r *http.Request, claims *TokenClaims)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		authorizationHeader := r.Header.Get("Authorization")
		if authorizationHeader != "" {
			bearerToken := strings.Split(authorizationHeader, " ")
			if len(bearerToken) == 2 {

				tok, err := jwt.ParseSigned(bearerToken[1])
				if err != nil {
					writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-auth-01, could not parse token: %v", bearerToken[1])
					return
				}

				claims := &TokenClaims{}

				if tok.Headers[0].Algorithm == string(jose.RS256) {
					err = tok.Claims(privRSA.Public(), claims)
				} else if tok.Headers[0].Algorithm == string(jose.HS256) {
					err = tok.Claims(jwtKey, claims)
				} else if tok.Headers[0].Algorithm == string(jose.EdDSA) {
					err = tok.Claims(privEdDSA.Public(), claims)
				} else {
					writeErr(w, http.StatusUnauthorized, "invalid_client", "blocked", "ERR-auth-02, unknown algo: %v", bearerToken[1])
					return
				}

				if err != nil {
					writeErr(w, http.StatusUnauthorized, "invalid_client", "blocked", "ERR-auth-02, could not parse claims: %v", bearerToken[1])
					return
				}

				if claims.Expiry != nil && !claims.Expiry.Time().After(time.Now()) {
					writeErr(w, http.StatusBadRequest, "invalid_client", "refused", "ERR-auth-03, expired: %v", bearerToken[1])
					return
				}

				next(w, r, claims)
				return
			} else {
				writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-auth-04, could not split token: %v", bearerToken)
				return
			}
		}
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-auth-05, authorization header not set")
		return
	}
}

func checkRefreshToken(token string) (*RefreshClaims, error) {
	tok, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, fmt.Errorf("ERR-check-refresh-01, could not check sig %v", err)
	}
	refreshClaims := &RefreshClaims{}
	if tok.Headers[0].Algorithm == string(jose.RS256) {
		err := tok.Claims(privRSA.Public(), refreshClaims)
		if err != nil {
			return nil, fmt.Errorf("ERR-check-refresh-02, could not parse claims %v", err)
		}
	} else if tok.Headers[0].Algorithm == string(jose.HS256) {
		err := tok.Claims(jwtKey, refreshClaims)
		if err != nil {
			return nil, fmt.Errorf("ERR-check-refresh-03, could not parse claims %v", err)
		}
	} else if tok.Headers[0].Algorithm == string(jose.EdDSA) {
		err := tok.Claims(privEdDSA.Public(), refreshClaims)
		if err != nil {
			return nil, fmt.Errorf("ERR-check-refresh-04, could not parse claims %v", err)
		}
	} else {
		return nil, fmt.Errorf("ERR-check-refresh-05, could not parse claims, no algo found %v", tok.Headers[0].Algorithm)
	}
	t := time.Unix(refreshClaims.ExpiresAt, 0)
	if !t.After(time.Now()) {
		return nil, fmt.Errorf("ERR-check-refresh-06, expired %v", err)
	}
	return refreshClaims, nil
}

func confirmEmail(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	token := vars["token"]
	email := vars["email"]

	err := updateEmailToken(email, token)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-confirm-email-01, update email token for %v failed, token %v: %v", email, token, err)
		return
	}

	w.WriteHeader(http.StatusOK)
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

	rnd, err := genRnd(48)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-signup-04, RND %v err %v", cred.Email, err)
		return
	}
	emailToken := base32.StdEncoding.EncodeToString(rnd[0:16])

	//https://security.stackexchange.com/questions/11221/how-big-should-salt-be

	salt := rnd[16:32]
	dk, err := scrypt.Key([]byte(cred.Password), salt, 16384, 8, 1, 32)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-signup-05, key %v error: %v", cred.Email, err)
		return
	}

	refreshToken := base32.StdEncoding.EncodeToString(rnd[32:48])

	err = insertUser(salt, cred.Email, dk, "USR", emailToken, refreshToken)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-signup-06, insert user failed: %v", err)
		return
	}

	url := strings.Replace(options.UrlEmail, "{email}", url.QueryEscape(cred.Email), 1)
	url = strings.Replace(url, "{token}", emailToken, 1)
	url = strings.Replace(url, "{action}", "signup", 1)

	err = sendEmail(url)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-signup-07, send email failed: %v", url)
		return
	}

	err = updateMailStatus(cred.Email)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-signup-08, db update failed: %v", err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func checkEmailPassword(email string, password string) (*dbRes, string, error) {
	result, err := dbSelect(email)
	if err != nil {
		return nil, "not-found", fmt.Errorf("ERR-checkEmail-01, DB select, %v err %v", email, err)
	}

	if result.emailVerified == nil || result.emailVerified.Unix() == 0 {
		return nil, "blocked", fmt.Errorf("ERR-checkEmail-02, user %v no email verified: %v", email, err)
	}

	if *result.errorCount > 2 {
		return nil, "blocked", fmt.Errorf("ERR-checkEmail-03, user %v no email verified: %v", email, err)
	}

	dk, err := scrypt.Key([]byte(password), result.salt, 16384, 8, 1, 32)
	if err != nil {
		return nil, "blocked", fmt.Errorf("ERR-checkEmail-04, key %v error: %v", email, err)
	}

	if bytes.Compare(dk, result.password) != 0 {
		err = incErrorCount(email)
		if err != nil {
			return nil, "blocked", fmt.Errorf("ERR-checkEmail-05, key %v error: %v", email, err)
		}
		return nil, "refused", fmt.Errorf("ERR-checkEmail-06, user %v password mismatch", email)
	}
	err = resetCount(email)
	if err != nil {
		return nil, "blocked", fmt.Errorf("ERR-checkEmail-05, key %v error: %v", email, err)
	}
	return result, "", nil
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
			url := strings.Replace(options.UrlSMS, "{sms}", *result.sms, 1)
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
		encoded, _, err := encodeCodeToken(cred.Email, cred.CodeChallenge, cred.CodeCodeChallengeMethod)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "invalid_request", "blocked", "ERR-login-14, cannot set refresh token for %v, %v", cred.Email, err)
			return
		}
		w.Header().Set("Location", cred.RedirectUri+"?code="+encoded)
		w.WriteHeader(303)
	} else {
		refreshToken, err := resetRefreshToken(*result.refreshToken)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_grant", "blocked", "ERR-login-15, cannot reset refresh token %v", err)
			return
		}
		encodedAccessToken, encodedRefreshToken, expiresAt, err := refresh(cred.Email, refreshToken)
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
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-reset-email-01, query unescape email %v err: %v", vars["email"], err)
		return
	}

	rnd, err := genRnd(16)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-reset-email-02, RND %v err %v", email, err)
		return
	}
	forgetEmailToken := base32.StdEncoding.EncodeToString(rnd)

	err = updateEmailForgotToken(email, forgetEmailToken)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-reset-email-03, update token for %v failed, token %v: %v", email, forgetEmailToken, err)
		return
	}

	url := strings.Replace(options.UrlEmail, "{email}", email, 1)
	url = strings.Replace(url, "{token}", forgetEmailToken, 1)
	url = strings.Replace(url, "{action}", "reset", 1)

	err = sendEmail(url)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-reset-email-04, send email failed: %v", url)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func confirmReset(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	email, err := url.QueryUnescape(vars["email"])
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-confirm-reset-email-01, query unescape email %v err: %v", vars["email"], err)
		return
	}

	token, err := url.QueryUnescape(vars["token"])
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-confirm-reset-email-02, query unescape token %v err: %v", vars["token"], err)
		return
	}

	var cred Credentials
	err = json.NewDecoder(r.Body).Decode(&cred)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-confirm-reset-email-03, cannot parse JSON credentials %v", err)
		return
	}

	err = validatePassword(cred.Password)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-confirm-reset-email-04, password is wrong %v", err)
		return
	}

	salt, err := genRnd(16)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-confirm-reset-email-05, RND %v err %v", email, err)
		return
	}

	dk, err := scrypt.Key([]byte(cred.Password), salt, 16384, 8, 1, 32)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid_request", "blocked", "ERR-confirm-reset-email-06, key %v error: %v", cred.Email, err)
		return
	}

	err = resetPassword(salt, email, dk, token)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-confirm-reset-email-07, update user failed: %v", err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func setupTOTP(w http.ResponseWriter, _ *http.Request, claims *TokenClaims) {
	rnd, err := genRnd(20)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-setup-totp-01, RND %v err %v", claims.Subject, err)
		return
	}

	secret := base32.StdEncoding.EncodeToString(rnd)
	err = updateTOTP(claims.Subject, secret)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-setup-totp-02, update failed %v err %v", claims.Subject, err)
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

	rnd, err := genRnd(20)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-setup-sms-02, RND %v err %v", claims.Subject, err)
		return
	}
	secret := base32.StdEncoding.EncodeToString(rnd)
	err = updateSMS(claims.Subject, secret, sms)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-setup-sms-03, updateSMS failed %v err %v", claims.Subject, err)
		return
	}

	totp := newTOTP(secret)

	url := strings.Replace(options.UrlSMS, "{sms}", sms, 1)
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
	w.Write([]byte(`{"version":"` + version + `"}`))
}

func jwkFunc(w http.ResponseWriter, r *http.Request) {
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

func serverLdap() (*ldap.Server, <-chan bool) {
	routes := ldap.NewRouteMux()
	routes.Bind(handleBind)
	routes.Search(handleSearch)

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

func serverRest() (*http.Server, <-chan bool, error) {
	tokenExp = time.Second * time.Duration(options.ExpireAccess)
	refreshExp = time.Second * time.Duration(options.ExpireRefresh)
	codeExp = time.Second * time.Duration(options.ExpireCode)

	router := mux.NewRouter()
	router.Use(func(next http.Handler) http.Handler {
		return handlers.LoggingHandler(os.Stdout, next)
	})

	if options.UserEndpoints {
		router.HandleFunc("/login", login).Methods("POST")
		router.HandleFunc("/signup", signup).Methods("POST")
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
		router.HandleFunc("/oauth/login", login).Methods("POST")
		router.HandleFunc("/oauth/token", oauth).Methods("POST")
		router.HandleFunc("/oauth/revoke", revoke).Methods("POST")
		router.HandleFunc("/oauth/authorize", authorize).Methods("GET")
		router.HandleFunc("/oauth/.well-known/jwks.json", jwkFunc).Methods("GET")

		router.HandleFunc("/authen/logout", logout).Methods("GET")
	}

	router.PathPrefix("/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("no route matched for: %v", r.URL)
		w.WriteHeader(http.StatusNotFound)
	})

	s := &http.Server{
		Addr:         ":" + strconv.Itoa(options.Port),
		Handler:      router,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	l, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return nil, nil, err
	}

	done := make(chan bool)
	go func(s *http.Server, l net.Listener) {
		log.Printf("Starting auth server on port %v...", s.Addr)
		if err := s.Serve(l); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
		log.Printf("Shutdown\n")
		done <- true
	}(s, l)
	return s, done, nil
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

func writeErr(w http.ResponseWriter, code int, error string, detailError string, format string, a ...interface{}) {
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
	w.Write([]byte(`{"error":"` + error + `","error_uri":"https://host:port/error-descriptions/authorization-request/` + error + `/` + detailError + `"` + msg + `}`))
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

func encodeAccessToken(role string, subject string, scope string, audience string, issuer string) (string, error) {
	tokenClaims := &TokenClaims{
		Role:  role,
		Scope: scope,
		Claims: jwt.Claims{
			Expiry:   jwt.NewNumericDate(time.Now().Add(tokenExp)),
			Subject:  subject,
			Audience: []string{audience},
			Issuer:   issuer,
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

func encodeRefreshToken(subject string, token string) (string, int64, error) {
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

func encodeCodeToken(subject string, codeChallenge string, codeChallengeMethod string) (string, int64, error) {
	cc := &CodeClaims{}
	cc.Subject = subject
	cc.ExpiresAt = time.Now().Add(codeExp).Unix()
	cc.CodeChallenge = codeChallenge
	cc.CodeCodeChallengeMethod = codeChallengeMethod

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
	codeToken, err := jwt.Signed(sig).Claims(cc).CompactSerialize()
	if err != nil {
		return "", 0, fmt.Errorf("JWT refresh token %v failed: %v", subject, err)
	}
	fmt.Printf("[%s]", codeToken)
	return codeToken, cc.ExpiresAt, nil
}

/*
 If the option ResetRefresh is set, then every time this function is called, which is
 before the createRefreshToken, then the refresh token is renewed and the old one is
 not valid anymore.

 This function is also used in case of revoking a token, where a new token is created,
 but not returned to the user, so the user has to login to get the refresh token
*/
func resetRefreshToken(oldToken string) (string, error) {
	rnd, err := genRnd(16)
	if err != nil {
		return "", err
	}
	newToken := base32.StdEncoding.EncodeToString(rnd)
	err = updateRefreshToken(oldToken, newToken)
	if err != nil {
		return "", err
	}
	return newToken, nil
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
	serverRest, doneChannelRest, err := serverRest()
	if err != nil {
		log.Fatal(err)
	}
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
