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
	options *Opts
	jwtKey  = []byte(os.Getenv("FFS_KEY"))
	db      *sql.DB
	exp     time.Duration
)

type Opts struct {
	Port     int    `short:"p" long:"port" description:"Port to listen on" default:"8080"`
	DBPath   string `short:"d" long:"dbpath" description:"Path to the DB file" default:"."`
	Url      string `short:"u" long:"url" description:"URL to email service, e.g., https://email.com/send/email/{email}/{token}" default:"http://localhost:8080/send/email/{email}/{token}"`
	Audience string `short:"a" long:"aud" description:"Audience comma separated string, e.g., FFS_FE, FFS_DB"`
	Expires  int    `short:"e" long:"exp" description:"Token expiration days, e.g., 7" default:"7"`
}

type Credentials struct {
	Password string `json:"password"`
	Email    string `json:"email"`
}
type Claims struct {
	Role string
	jwt.StandardClaims
}

func auth(next func(w http.ResponseWriter, r *http.Request, claims *Claims), expiredAllowed bool) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		authorizationHeader := r.Header.Get("Authorization")
		if authorizationHeader != "" {
			bearerToken := strings.Split(authorizationHeader, " ")
			if len(bearerToken) == 2 {
				claims := &Claims{}
				token, err := jwt.ParseWithClaims(bearerToken[1], claims, func(token *jwt.Token) (i interface{}, err error) {
					return jwtKey, nil
				})

				v, _ := err.(*jwt.ValidationError)
				if v.Errors == jwt.ValidationErrorExpired && claims.ExpiresAt < time.Now().Unix() {
					writeErr(w, http.StatusUnauthorized, "AU01, could not parse token %v", err)
					return
				}

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

func refresh(w http.ResponseWriter, r *http.Request, claims *Claims) {
	//check if refresh token matches
	c, err := r.Cookie("refresh")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "RE01, Cookie parsing %v failed: %v", claims.Subject, err)
		return
	}

	dbRefreshToken, err := getRefreshToken(claims.Subject)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "RE02, DB refresh token %v failed: %v", claims.Subject, err)
		return
	}

	if c.Value != dbRefreshToken {
		writeErr(w, http.StatusUnauthorized, "RE03, JWT/refresh %v failed: %v", claims.Subject, err)
		return
	}

	//new expiry date
	claims.ExpiresAt = time.Now().Add(exp).Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "RE04, JWT %v failed: %v", claims.Subject, err)
		return
	}

	w.Header().Set("token", tokenString)
	cookie := http.Cookie{Name: "refresh", Value: dbRefreshToken, Path: "/refresh", HttpOnly: true}
	w.Header().Set("Set-Cookie", cookie.String())
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

	rnd, err := genRnd(32)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "SI03, RND %v err %v", cred.Email, err)
		return
	}
	emailToken := hex.EncodeToString(rnd[0:16])

	//https://security.stackexchange.com/questions/11221/how-big-should-salt-be
	err = insertUser(rnd[16:32], cred.Email, cred.Password, emailToken)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "SI04, insert user failed: %v", err)
		return
	}

	url := strings.Replace(options.Url, "{email}", url.QueryEscape(cred.Email), 1)
	url = strings.Replace(url, "{token}", emailToken, 1)

	err = sendEmail(url)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "SI05, send email failed: %v", url)
		return
	}

	err = dbUpdateMailStatus(cred.Email)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "SI06, db update failed: %v", err)
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
		writeErr(w, http.StatusBadRequest, "LO03, DB select, %v err %v", cred.Email, err)
		return
	}

	if result.activated.Unix() == 0 {
		writeErr(w, http.StatusUnauthorized, "LO04, user %v is not activated failed: %v", cred.Email, err)
		return
	}

	dk, err := scrypt.Key([]byte(cred.Password), result.salt, 32768, 8, 1, 32)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "LO05, user %v password: %v", cred.Email, err)
		return
	}

	if bytes.Compare(dk, result.password) != 0 {
		writeErr(w, http.StatusUnauthorized, "LO06, user %v password mismatch", cred.Email)
		return
	}

	claims := &Claims{
		Role: string(result.role),
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(exp).Unix(),
			Id:        hex.EncodeToString(result.id),
			Subject:   cred.Email,
		},
	}

	refresh(w, r, claims)
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

	exp = time.Hour * 24 * time.Duration(opts.Expires)

	router := mux.NewRouter()
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/signin", signin).Methods("POST")
	router.HandleFunc("/refresh", auth(refresh, true)).Methods("GET")

	//TODO: implement reset pw via email
	router.HandleFunc("/reset/email/{email}", nil).Methods("GET")
	router.HandleFunc("/reset/totp", nil).Methods("GET")

	//TODO: implement 2FA with TOTP
	router.HandleFunc("/setup/totp", nil).Methods("GET")

	//TODO: implement 2FA with SMS
	router.HandleFunc("/setup/sms/setup", nil).Methods("GET")

	//TODO: implement 2FA with TOTP
	router.HandleFunc("/confirm/totp/{totp-token}", nil).Methods("GET")

	//TODO: implement 2FA with SMS
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
