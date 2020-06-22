package main

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/jessevdk/go-flags"
	_ "github.com/mattn/go-sqlite3"
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

type Opts struct {
	Port     int    `short:"p" long:"port" description:"Port to listen on" default:"8080"`
	DBPath   string `long:"db" description:"Path to the DB file" default:"."`
	Url      string `short:"u" long:"url" description:"URL to email service, e.g., https://email.com/send/email/{email}/{token}" default:"http://localhost:8080/send/email/{email}/{token}"`
	Audience string `short:"a" long:"aud" description:"Audience comma separated string, e.g., FFS_FE, FFS_DB"`
	Expires  int    `short:"t" long:"tokenExpires" description:"Token expiration minutes, e.g., 60" default:"60"`
	Refresh  int    `short:"r" long:"refreshExpires" description:"Refresh token expiration days, e.g., 7" default:"7"`
	Dev      bool   `short:"d" long:"dev" description:"Dev mode" default:"false"`
}

type Credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
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
					writeErr(w, http.StatusForbidden, "AU02, could not parse token %v", err)
					return
				}

				next(w, r, claims)
				return
			}
		}
		msg := fmt.Sprint("AU03, authorizationHeader not set")
		log.Print(msg)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(msg))
		return
	}
}

func refresh(w http.ResponseWriter, r *http.Request) {

	//https://medium.com/monstar-lab-bangladesh-engineering/jwt-auth-in-go-part-2-refresh-tokens-d334777ca8a0

	//check if refresh token matches
	c, err := r.Cookie("refresh")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "RE01, cookie not found: %v", err)
		return
	}
	refreshClaims := &RefreshClaims{}

	refreshToken, err := jwt.ParseWithClaims(c.Value, refreshClaims, func(token *jwt.Token) (i interface{}, err error) {
		return jwtKey, nil
	})

	if err != nil || !refreshToken.Valid {
		writeErr(w, http.StatusForbidden, "RE02, could not parse token %v", err)
		return
	}

	result, err := dbSelect(refreshClaims.Subject)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "RE03, DB select, %v err %v", refreshClaims.Subject, err)
		return
	}

	if result.activated == nil || result.activated.Unix() == 0 {
		writeErr(w, http.StatusUnauthorized, "RE04, user %v is not activated failed: %v", refreshClaims.Subject, err)
		return
	}

	if refreshClaims.Token != result.refreshToken {
		writeErr(w, http.StatusInternalServerError, "RE05, DB refresh token mismatch %v failed: %v", refreshClaims.Subject, err)
		return
	}

	setAccessToken(w, string(result.role), result.id, refreshClaims.Subject)
	setRefreshToken(w, refreshClaims.Subject, result.refreshToken)

	w.WriteHeader(http.StatusOK)
}

func confirm(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	token := vars["token"]
	email := vars["email"]

	err := updateToken(email, token)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "CO01, update token for %v failed, token %v: %v", email, token, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func signin(w http.ResponseWriter, r *http.Request) {
	var cred Credentials
	err := json.NewDecoder(r.Body).Decode(&cred)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "SI01, JSON, signin err %v", err)
		return
	}

	err = validateEmail(cred.Email)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "SI02, email is wrong %v", err)
	}

	err = validatePassword(cred.Password)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "SI03, email is wrong %v", err)
	}

	rnd, err := genRnd(32)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "SI04, RND %v err %v", cred.Email, err)
		return
	}
	emailToken := hex.EncodeToString(rnd[0:16])

	//https://security.stackexchange.com/questions/11221/how-big-should-salt-be

	salt := rnd[16:32]
	dk, err := scrypt.Key([]byte(cred.Password), salt, 16384, 8, 1, 32)
	err = insertUser(salt, cred.Email, dk, emailToken)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "SI05, insert user failed: %v", err)
		return
	}

	url := strings.Replace(options.Url, "{email}", url.QueryEscape(cred.Email), 1)
	url = strings.Replace(url, "{token}", emailToken, 1)

	err = sendEmail(url)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "SI06, send email failed: %v", url)
		return
	}

	err = dbUpdateMailStatus(cred.Email)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "SI07, db update failed: %v", err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func login(w http.ResponseWriter, r *http.Request) {
	var cred Credentials
	err := json.NewDecoder(r.Body).Decode(&cred)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "LO01, JSON, login err %v", err)
		return
	}

	err = validateEmail(cred.Email)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "LO02, email is wrong %v", err)
	}

	result, err := dbSelect(cred.Email)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "LO03, DB select, %v err %v", cred.Email, err)
		return
	}

	if result.activated == nil || result.activated.Unix() == 0 {
		writeErr(w, http.StatusUnauthorized, "LO04, user %v is not activated failed: %v", cred.Email, err)
		return
	}

	dk, err := scrypt.Key([]byte(cred.Password), result.salt, 16384, 8, 1, 32)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "LO05, user %v error: %v", cred.Email, err)
		return
	}

	if bytes.Compare(dk, result.password) != 0 {
		writeErr(w, http.StatusUnauthorized, "LO06, user %v password mismatch", cred.Email)
		return
	}

	err = setAccessToken(w, string(result.role), result.id, cred.Email)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "LO07, setAccessToken %v error: %v", cred.Email, err)
		return
	}
	err = setRefreshToken(w, cred.Email, result.refreshToken)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "LO08, setRefreshToken %v error: %v", cred.Email, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func setAccessToken(w http.ResponseWriter, role string, id []byte, subject string) error {

	tokenClaims := &TokenClaims{
		Role: role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(tokenExp).Unix(),
			Id:        hex.EncodeToString(id),
			Subject:   subject,
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, tokenClaims)
	accessTokenString, err := accessToken.SignedString(jwtKey)
	if err != nil {
		return fmt.Errorf("JWT %v failed: %v", tokenClaims.Subject, err)
	}
	w.Header().Set("Token", accessTokenString)
	return nil
}

func setRefreshToken(w http.ResponseWriter, subject string, token string) error {
	rc := &RefreshClaims{}
	rc.Subject = subject
	rc.ExpiresAt = time.Now().Add(refreshExp).Unix()
	rc.Token = token
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS512, rc)
	rt, err := refreshToken.SignedString(jwtKey)
	if err != nil {
		return fmt.Errorf("JWT2 %v failed: %v", subject, err)
	}

	cookie := http.Cookie{
		Name:     "refresh",
		Value:    rt,
		Path:     "/refresh",
		HttpOnly: true,
		Secure:   !options.Dev,
		Expires:  time.Now().Add(refreshExp),
	}
	w.Header().Set("Set-Cookie", cookie.String())
	return nil
}

func send(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	token := vars["token"]
	email, err := url.QueryUnescape(vars["email"])
	if err != nil {
		log.Printf("decoding error %v", err)
	}

	fmt.Printf("go to URL: http://%s/confirm/%s/%s\n", r.Host, email, token)
	r.Body.Close()
	w.WriteHeader(http.StatusOK)
}

func main() {
	var opts Opts
	_, err := flags.NewParser(&opts, flags.None).Parse()
	if err != nil {
		log.Fatal(err)
	}

	_, doneChannel := server(&opts)
	<-doneChannel
}

func server(opts *Opts) (*http.Server, <-chan bool) {
	options = opts

	tokenExp = time.Minute * time.Duration(opts.Expires)
	refreshExp = time.Hour * 24 * time.Duration(opts.Refresh)

	router := mux.NewRouter()
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/signin", signin).Methods("POST")
	router.HandleFunc("/refresh", refresh).Methods("GET")

	//TODO: implement reset pw via email
	router.HandleFunc("/reset/email/{email}", nil).Methods("GET")

	//TODO: implement reset TOTP, SMS via email
	router.HandleFunc("/reset/totp/{email}", nil).Methods("GET")
	router.HandleFunc("/reset/sms/{email}", nil).Methods("GET")

	//TODO: implement 2FA with TOTP, SMS
	router.HandleFunc("/setup/totp", nil).Methods("GET")
	router.HandleFunc("/setup/sms/setup", nil).Methods("GET")

	//TODO: implement 2FA with TOTP, SMS
	router.HandleFunc("/confirm/totp/{totp-token}", nil).Methods("GET")
	router.HandleFunc("/confirm/sms/{sms-token}", nil).Methods("GET")
	router.HandleFunc("/confirm/email/{email}/{token}", confirm).Methods("GET")

	//display for debug and testing
	router.HandleFunc("/send/email/{email}/{token}", send).Methods("GET")
	router.HandleFunc("/send/sms/{sms-nr}/{token}", send).Methods("GET")

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
	file, err := ioutil.ReadFile("startup.sql")
	if err != nil {
		return nil, err
	}

	requests := strings.Split(string(file), ";")
	for _, request := range requests {
		request = strings.Replace(request, "\n", "", -1)
		request = strings.Replace(request, "\t", "", -1)
		_, err = db.Exec(request)
		if err != nil {
			return nil, fmt.Errorf("[%v] %v", request, err)
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
	w.WriteHeader(code)
	w.Write([]byte(msg))
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
