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
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/kjk/dailyrotate"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	ldap "github.com/vjeantet/ldapserver"
	"github.com/xlzd/gotp"
	ed25519 "golang.org/x/crypto/ed25519"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"hash/crc64"
	"log"
	rnd "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	opts         *Opts
	jwtKey       []byte
	privRSA      *rsa.PrivateKey
	privRSAKid   string
	privEdDSA    *ed25519.PrivateKey
	privEdDSAKid string
	db           *sql.DB
	tokenExp     time.Duration
	refreshExp   time.Duration
	codeExp      time.Duration
	hoursAdd     int
	logFile      *dailyrotate.File
	admins       []string
)

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
	//Token stuff
	EmailToken  string `json:"email_token,omitempty" schema:"email_token"`
	InviteEmail string `json:"inviteEmail,omitempty"`
	ExpireAt    string `json:"expireAt,omitempty"`
	InviteToken string `json:"inviteToken,omitempty"`
	InviteMeta  string `json:"inviteMeta,omitempty"`
}

type TokenClaims struct {
	Scope            string                 `json:"scope,omitempty"`
	InviteToken      string                 `json:"inviteToken,omitempty"`
	InviteMetaSystem map[string]interface{} `json:"inviteMetaSystem,omitempty"`
	InviteMetaUser   map[string]interface{} `json:"inviteMetaUser,omitempty"`
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

type OAuth struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	Expires      string `json:"expires_in"`
}

type Opts struct {
	Env             string
	Dev             string
	Issuer          string
	Port            int
	Ldap            int
	DBPath          string
	DBDriver        string
	DBScripts       string
	EmailFrom       string
	EmailFromName   string
	EmailUrl        string
	EmailToken      string
	EmailLinkPrefix string
	UrlSms          string
	SmsToken        string
	Audience        string
	ExpireAccess    int
	ExpireRefresh   int
	ExpireCode      int
	HS256           string
	EdDSA           string
	RS256           string
	OAuthUser       string
	OAuthPass       string
	ResetRefresh    bool
	Users           string
	UserEndpoints   bool
	OauthEndpoints  bool
	LdapServer      bool
	DetailedError   bool
	Redirects       string
	PasswordFlow    bool
	Scope           string
	LogPath         string
	Admins          string
}

func NewOpts() *Opts {
	err := godotenv.Load()
	if err != nil {
		log.Printf("Could not find env file [%v], using defaults", err)
	}

	opts := &Opts{}
	flag.StringVar(&opts.Env, "env", lookupEnv("ENV", "local"), "ENV variable")
	flag.StringVar(&opts.Dev, "dev", lookupEnv("DEV"), "Dev settings with initial secret")
	flag.StringVar(&opts.Issuer, "issuer", lookupEnv("ISSUER"), "name of issuer, default in dev is my-issuer")
	flag.IntVar(&opts.Port, "port", lookupEnvInt("PORT",
		8080), "listening HTTP port")
	flag.IntVar(&opts.Ldap, "ldap", lookupEnvInt("LDAP",
		8389), "listening LDAP port")
	flag.StringVar(&opts.DBPath, "db-path", lookupEnv("DB_PATH",
		"./fastauth.db"), "DB path")
	flag.StringVar(&opts.DBDriver, "db-driver", lookupEnv("DB_DRIVER",
		"sqlite3"), "DB driver")
	flag.StringVar(&opts.DBScripts, "db-scripts", lookupEnv("DB_SCRIPTS"), "DB scripts to run at startup")
	flag.StringVar(&opts.EmailFrom, "email-from", lookupEnv("EMAIL_FROM"), "Email from, default is info@flatfeestack.io")
	flag.StringVar(&opts.EmailFromName, "email-from-name", lookupEnv("EMAIL_FROM_NAME",
		"email@fastauth"), "Email from name, default is a empty string")
	flag.StringVar(&opts.EmailUrl, "email-url", lookupEnv("EMAIL_URL"), "Email service URL")
	flag.StringVar(&opts.EmailToken, "email-token", lookupEnv("EMAIL_TOKEN"), "Email service token")
	flag.StringVar(&opts.EmailLinkPrefix, "email-prefix", lookupEnv("EMAIL_PREFIX"), "Email link prefix")
	flag.StringVar(&opts.UrlSms, "sms-url", lookupEnv("SMS_URL"), "SMS service URL")
	flag.StringVar(&opts.SmsToken, "sms-token", lookupEnv("SMS_TOKEN"), "SMS service token")
	flag.StringVar(&opts.Audience, "audience", lookupEnv("AUDIENCE"), "Audience, default in dev is my-audience")
	flag.IntVar(&opts.ExpireAccess, "expire-access", lookupEnvInt("EXPIRE_ACCESS",
		30*60), "Access token expiration in seconds, default 30min")
	flag.IntVar(&opts.ExpireRefresh, "expire-refresh", lookupEnvInt("EXPIRE_REFRESH",
		180*24*60*60), "Refresh token expiration in seconds, default 6month")
	flag.IntVar(&opts.ExpireCode, "expire-code", lookupEnvInt("EXPIRE_CODE",
		60), "Authtoken flow expiration in seconds, default 1min")
	flag.StringVar(&opts.HS256, "hs256", lookupEnv("HS256"), "HS256 key")
	flag.StringVar(&opts.RS256, "rs256", lookupEnv("RS256"), "RS256 key")
	flag.StringVar(&opts.EdDSA, "eddsa", lookupEnv("EDDSA"), "EdDSA key")
	flag.BoolVar(&opts.ResetRefresh, "reset-refresh", lookupEnv("RESET_REFRESH") != "", "Reset refresh token when setting the token")
	flag.StringVar(&opts.Users, "users", lookupEnv("USERS"), "add these initial users. E.g, -users tom@test.ch:pw123;test@test.ch:123pw")
	flag.BoolVar(&opts.UserEndpoints, "user-endpoints", lookupEnv("USER_ENDPOINTS") != "", "Enable user-facing endpoints. In dev mode these are enabled by default")
	flag.BoolVar(&opts.OauthEndpoints, "oauth-enpoints", lookupEnv("OAUTH_ENDPOINTS") != "", "Enable oauth-facing endpoints. In dev mode these are enabled by default")
	flag.BoolVar(&opts.LdapServer, "ldap-server", lookupEnv("LDAP_SERVER") != "", "Enable ldap server. In dev mode these are enabled by default")
	flag.BoolVar(&opts.DetailedError, "details", lookupEnv("DETAILS") != "", "Enable detailed errors")
	flag.StringVar(&opts.Redirects, "redir", lookupEnv("REDIR"), "add client redirects. E.g, -redir clientId1:http://blabla;clientId2:http://blublu")
	flag.BoolVar(&opts.PasswordFlow, "pwflow", lookupEnv("PWFLOW") != "", "enable password flow, default disabled")
	flag.StringVar(&opts.Scope, "scope", lookupEnv("SCOPE"), "scope, default in dev is my-scope")
	flag.StringVar(&opts.LogPath, "log", lookupEnv("LOG",
		os.TempDir()+"/ffs"), "Log directory, default is /tmp/ffs")
	flag.StringVar(&opts.Admins, "admins", lookupEnv("ADMINS"), "Admins")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	//set defaults
	if opts.Dev != "" {
		if opts.Scope == "" {
			opts.Scope = "my-scope"
		}
		if opts.Audience == "" {
			opts.Audience = "my-audience"
		}
		if opts.Issuer == "" {
			opts.Issuer = "my-issuer"
		}
		if opts.EmailUrl == "" {
			opts.EmailUrl = "http://localhost:8080/send/email/{email}/{token}"
		}
		if opts.UrlSms == "" {
			opts.UrlSms = "http://localhost:8080/send/sms/{sms}/{token}"
		}

		h := crc64.MakeTable(0xC96C5795D7870F42)
		if strings.ToLower(opts.RS256) != "true" && strings.ToLower(opts.EdDSA) != "true" {
			opts.HS256 = base32.StdEncoding.EncodeToString([]byte(opts.Dev))
		} else if strings.ToLower(opts.HS256) != "true" && strings.ToLower(opts.EdDSA) != "true" {
			rsaPrivKey, err := rsa.GenerateKey(rnd.New(rnd.NewSource(int64(crc64.Checksum([]byte(opts.Dev), h)))), 2048)
			if err != nil {
				log.Fatalf("cannot generate rsa key %v", err)
			}
			encPrivRSA, err := x509.MarshalPKCS8PrivateKey(rsaPrivKey)
			if err != nil {
				log.Fatalf("cannot generate rsa key %v", err)
			}
			opts.RS256 = base32.StdEncoding.EncodeToString(encPrivRSA)
		} else if strings.ToLower(opts.HS256) != "true" && strings.ToLower(opts.RS256) != "true" {
			_, edPrivKey, err := ed25519.GenerateKey(rnd.New(rnd.NewSource(int64(crc64.Checksum([]byte(opts.Dev), h)))))
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

	admins = strings.Split(opts.Admins, ";")

	if opts.HS256 == "" && opts.RS256 == "" && opts.EdDSA == "" {
		fmt.Printf("Paramter hs256, rs256, or eddsa not set. One of them is mandatory. Choose one\n")
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
		rsaDec, err := base32.StdEncoding.DecodeString(opts.RS256)
		if err != nil {
			log.Fatalf("cannot decode %v", opts.RS256)
		}
		i, err := x509.ParsePKCS8PrivateKey(rsaDec)
		if err != nil {
			log.Fatalf("cannot decode %v", rsaDec)
		}
		privRSA = i.(*rsa.PrivateKey)
		k := jose.JSONWebKey{Key: privRSA.Public()}
		kid, err := k.Thumbprint(crypto.SHA256)
		if err != nil {
			log.Fatalf("cannot thumb rsa %v", err)
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
			log.Fatalf("cannot thumb eddsa %v", err)
		}
		privEdDSAKid = hex.EncodeToString(kid)
	}

	pathFormat := filepath.Join(opts.LogPath, "auth_2006-01-02.txt")
	w, err := dailyrotate.NewFile(pathFormat, func(string, bool) {})
	if err != nil {
		log.Fatalf("cannot log")
	}
	logFile = w

	return opts
}

func lookupEnv(key string, defaultValues ...string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	for _, v := range defaultValues {
		if v != "" {
			return v
		}
	}
	return ""
}

func lookupEnvInt(key string, defaultValues ...int) int {
	if val, ok := os.LookupEnv(key); ok {
		v, err := strconv.Atoi(val)
		if err != nil {
			log.Printf("LookupEnvInt[%s]: %v", key, err)
			return 0
		}
		return v
	}
	for _, v := range defaultValues {
		if v != 0 {
			return v
		}
	}
	return 0
}

func checkEmailPassword(email string, password string) (*dbRes, string, error) {
	result, err := findAuthByEmail(email)
	if err != nil {
		return nil, "not-found", fmt.Errorf("ERR-checkEmail-01, DB select, %v err %v", email, err)
	}

	if result.emailToken != nil {
		return nil, "blocked", fmt.Errorf("ERR-checkEmail-02, user %v no email verified: %v", email, err)
	}

	if result.errorCount > 2 {
		return nil, "blocked", fmt.Errorf("ERR-checkEmail-03, user %v no email verified: %v", email, err)
	}

	storedPw, calcPw, err := checkPw(password, result.password)
	if err != nil {
		return nil, "blocked", fmt.Errorf("ERR-checkEmail-04, key %v error: %v", email, err)
	}

	if bytes.Compare(calcPw, storedPw) != 0 {
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

func serverLdap() (*ldap.Server, <-chan bool) {
	routes := ldap.NewRouteMux()
	routes.Bind(handleBind)
	routes.Search(handleSearch)

	server := ldap.NewServer()
	server.Handle(routes)

	done := make(chan bool)
	if opts.LdapServer {
		go func(s *ldap.Server) {
			addr := ":" + strconv.Itoa(opts.Ldap)
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

func serverRest(keepAlive bool) (*http.Server, <-chan bool, error) {
	tokenExp = time.Second * time.Duration(opts.ExpireAccess)
	refreshExp = time.Second * time.Duration(opts.ExpireRefresh)
	codeExp = time.Second * time.Duration(opts.ExpireCode)

	router := mux.NewRouter()
	router.Use(func(next http.Handler) http.Handler {
		return logRequestHandler(next)
	})

	if opts.UserEndpoints {
		router.HandleFunc("/login", login).Methods(http.MethodPost)
		router.HandleFunc("/refresh", refresh).Methods(http.MethodPost)
		router.HandleFunc("/signup", signup).Methods(http.MethodPost)
		router.HandleFunc("/reset/{email}", resetEmail).Methods(http.MethodPost)
		router.HandleFunc("/confirm/signup/{email}/{token}", confirmEmail).Methods(http.MethodGet)
		router.HandleFunc("/confirm/signup", confirmEmailPost).Methods(http.MethodPost)
		router.HandleFunc("/confirm/reset", confirmReset).Methods(http.MethodPost)
		router.HandleFunc("/setup/totp", jwtAuth(setupTOTP)).Methods(http.MethodPost)
		router.HandleFunc("/confirm/totp/{token}", jwtAuth(confirmTOTP)).Methods(http.MethodPost)
		router.HandleFunc("/setup/sms/{sms}", jwtAuth(setupSMS)).Methods(http.MethodPost)
		router.HandleFunc("/confirm/sms/{token}", jwtAuth(confirmSMS)).Methods(http.MethodPost)
	}
	//logout
	router.HandleFunc("/authen/logout", jwtAuth(logout)).Methods(http.MethodGet)

	//maintenance stuff
	router.HandleFunc("/readiness", readiness).Methods(http.MethodGet)
	router.HandleFunc("/liveness", liveness).Methods(http.MethodGet)

	//display for debug and testing
	if opts.Env == "dev" || opts.Env == "local" {
		router.HandleFunc("/send/email/{email}/{token}", displayEmail).Methods(http.MethodPost)
		router.HandleFunc("/send/sms/{sms}/{token}", displaySMS).Methods(http.MethodPost)
	}

	if opts.Env == "dev" || opts.Env == "local" {
		router.HandleFunc("/timewarp/{hours}", timeWarp).Methods(http.MethodPost)
	}

	if opts.OauthEndpoints {
		router.HandleFunc("/oauth/login", login).Methods(http.MethodPost)
		router.HandleFunc("/oauth/token", basicAuth(oauth)).Methods(http.MethodPost)
		router.HandleFunc("/oauth/revoke", jwtAuth(revoke)).Methods(http.MethodPost)
		router.HandleFunc("/oauth/authorize", authorize).Methods(http.MethodGet)
		//convenience function
		if opts.Env == "dev" || opts.Env == "local" {
			router.HandleFunc("/", authorize).Methods(http.MethodGet)
		}
		router.HandleFunc("/oauth/.well-known/jwks.json", jwkFunc).Methods(http.MethodGet)
	}

	router.HandleFunc("/admin/login-as/{email}", jwtAuthAdmin(asUser, admins)).Methods(http.MethodPost)

	router.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[404] no route matched for: %s, %s", r.URL, r.Method)
		w.WriteHeader(http.StatusNotFound)
	})

	s := &http.Server{
		Addr:         ":" + strconv.Itoa(opts.Port),
		Handler:      router,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	s.SetKeepAlivesEnabled(keepAlive)

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

func genToken() (string, error) {
	rnd, err := genRnd(20)
	if err != nil {
		return "", err
	}
	return base32.StdEncoding.EncodeToString(rnd), nil
}

func writeErr(w http.ResponseWriter, code int, error string, detailError string, format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	log.Printf(msg)
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(code)
	if opts.DetailedError {
		msg = `,"error_message":"` + msg + `"`
	} else {
		msg = ""
	}
	w.Write([]byte(`{"error":"` + error + `","error_uri":"https://host:port/error-descriptions/authorization-request/` + error + `/` + detailError + `"` + msg + `}`))
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

func basicAuth(next func(w http.ResponseWriter, r *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if opts.OAuthUser != "" || opts.OAuthPass != "" {
			user, pass, ok := r.BasicAuth()
			if !ok || user != opts.OAuthUser || pass != opts.OAuthPass {
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
		}
		next(w, r)
	}
}

func param(name string, r *http.Request) (string, error) {
	n1 := mux.Vars(r)[name]
	n2, err := url.QueryUnescape(r.URL.Query().Get(name))
	if err != nil {
		return "", err
	}
	err = r.ParseForm()
	if err != nil {
		return "", err
	}
	n3 := r.FormValue(name)

	if n1 == "" {
		if n2 == "" {
			return n3, nil
		}
		return n2, nil
	}
	return n1, nil
}

func paramJson(name string, r *http.Request) (string, error) {
	var objmap map[string]json.RawMessage
	err := json.NewDecoder(r.Body).Decode(&objmap)
	if err != nil {
		return "", err
	}
	var s string
	err = json.Unmarshal(objmap[name], &s)
	if err != nil {
		return "", err
	}
	return s, nil
}

func timeNow() time.Time {
	if opts.Env == "local" || opts.Env == "dev" {
		return time.Now().Add(time.Duration(hoursAdd) * time.Hour)
	} else {
		return time.Now()
	}
}

func main() {
	f, err := os.Open("banner.txt")
	if err == nil {
		banner.Init(os.Stdout, true, false, f)
	} else {
		log.Printf("could not display banner...")
	}

	opts = NewOpts()

	//logs: we have to ensure the directory we want to write to
	// already exists
	err = os.MkdirAll(opts.LogPath, 0755)
	if err != nil {
		log.Fatalf("os.MkdirAll()")
	}

	//db: init the database
	db, err = initDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	setupDB()
	serverRest, doneChannelRest, err := serverRest(true)
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
}
