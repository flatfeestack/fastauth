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

func auth(next func(w http.ResponseWriter, r *http.Request, claims *Claims)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		authorizationHeader := req.Header.Get("Authorization")
		if authorizationHeader != "" {
			bearerToken := strings.Split(authorizationHeader, " ")
			if len(bearerToken) == 2 {
				claims := &Claims{}
				token, err := jwt.ParseWithClaims(bearerToken[1], claims, func(token *jwt.Token) (i interface{}, err error) {
					return jwtKey, nil
				})
				if err != nil || !token.Valid {
					writeErr(w, http.StatusBadRequest, "AU01, could not parse token %v", err)
					return
				}
				next(w, req, claims)
				return
			}
		}
		msg := fmt.Sprint("AU02, authorizationHeader not set")
		log.Print(msg)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(msg))
		return
	}
}

func refresh(w http.ResponseWriter, _ *http.Request, claims *Claims) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "RE01, JWT %v failed: %v", claims.Subject, err)
		return
	}

	w.Header().Set("token", tokenString)
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
	rnd, err := genRnd(32)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "SI02, RND %v err %v", cred.Email, err)
		return
	}
	t := hex.EncodeToString(rnd[0:16])

	stmt, err := db.Prepare("INSERT INTO users (email, password, role, salt, token) values (?, ?, 'USR', ?, ?)")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "SI03, prepare %v statement failed: %v", cred.Email, err)
		return
	}
	//https://security.stackexchange.com/questions/11221/how-big-should-salt-be
	salt := rnd[16:32]
	dk, err := scrypt.Key([]byte(cred.Password), salt, 32768, 8, 1, 32)
	res, err := stmt.Exec(cred.Email, dk, salt, t)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "SI04, query %v failed: %v", cred.Email, err)
		return
	}
	//TODO: if duplicate send email out again
	nr, err := res.RowsAffected()
	if nr == 0 || err != nil {
		writeErr(w, http.StatusBadRequest, "SI05, %v rows %v, affected or err: %v", nr, cred.Email, err)
		return
	}

	url := strings.Replace(options.Url, "{email}", url.QueryEscape(cred.Email), 1)
	url = strings.Replace(url, "{token}", t, 1)

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

	result, err := dbSelect(cred.Email)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "LO02, DB select, %v err %v", cred.Email, err)
		return
	}

	if result.activated.Unix() == 0 {
		writeErr(w, http.StatusUnauthorized, "LO03, user %v is not activated failed: %v", cred.Email, err)
		return
	}

	dk, err := scrypt.Key([]byte(cred.Password), result.salt, 32768, 8, 1, 32)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "LO04, user %v password: %v", cred.Email, err)
		return
	}

	if bytes.Compare(dk, result.password) != 0 {
		writeErr(w, http.StatusUnauthorized, "LO05, user %v password mismatch", cred.Email)
		return
	}

	claims := &Claims{
		Role: string(result.role),
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(exp).Unix(),
			Id:        hex.EncodeToString(result.id),
			Subject:   cred.Email,
			Audience:  options.Audience,
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
	router.HandleFunc("/refresh", auth(refresh)).Methods("GET")
	//TODO: implement reset pw via email
	router.HandleFunc("/reset/email/{email}", confirm).Methods("GET")
	//TODO: implement 2FA with TOTP
	//TODO: implement 2FA with SMS
	router.HandleFunc("/confirm/email/{email}/{token}", confirm).Methods("GET")
	router.HandleFunc("/send/email/{email}/{token}", send).Methods("GET")

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
