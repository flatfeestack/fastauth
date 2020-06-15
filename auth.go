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
	Url      string `short:"u" long:"url" description:"URL to email service, e.g., https://email.com/send/{email}/{token}/{lang}" default:"http://localhost:8080/send/{email}/{token}/{lang}"`
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

type dbRes struct {
	id        []byte
	password  []byte
	role      []byte
	salt      []byte
	activated time.Time
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
					log.Printf("could not parse token %v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				next(w, req, claims)
				return
			}
		}
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
}

func refresh(w http.ResponseWriter, _ *http.Request, claims *Claims) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		log.Printf("JWT %v failed: %v", claims.Subject, err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("token", tokenString)
	w.WriteHeader(http.StatusOK)
}

func confirm(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	token := vars["token"]
	email := vars["email"]
	stmt, err := db.Prepare("UPDATE users SET activated = datetime('now'), token = NULL where email = ? and token = ?")
	res, err := stmt.Exec(email, token)
	if err != nil {
		log.Printf("prepare statement failed: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	nr, err := res.RowsAffected()
	if nr == 0 || err != nil {
		log.Printf("%v rows %v, affected or err: %v", nr, email, err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func signin(w http.ResponseWriter, r *http.Request) {
	var cred Credentials
	err := json.NewDecoder(r.Body).Decode(&cred)
	if err != nil {
		log.Printf("JSON, signin err %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	rnd, err := genRnd(32)
	if err != nil {
		log.Printf("RND %v err %v", cred.Email, err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	t := hex.EncodeToString(rnd[0:16])

	stmt, err := db.Prepare("INSERT INTO users (email, password, role, salt, token) values (?, ?, 'USR', ?, ?)")
	if err != nil {
		log.Printf("prepare %v statement failed: %v", cred.Email, err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	//https://security.stackexchange.com/questions/11221/how-big-should-salt-be
	salt := rnd[16:32]
	dk, err := scrypt.Key([]byte(cred.Password), salt, 32768, 8, 1, 32)
	res, err := stmt.Exec(cred.Email, dk, salt, t)
	if err != nil {
		log.Printf("query %v failed: %v", cred.Email, err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	//TODO: if duplicate send email out again
	nr, err := res.RowsAffected()
	if nr == 0 || err != nil {
		log.Printf("%v rows %v, affected or err: %v", nr, cred.Email, err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	url := strings.Replace(options.Url, "{email}", url.QueryEscape(cred.Email), 1)
	url = strings.Replace(url, "{token}", t, 1)
	url = strings.Replace(url, "{lang}", "en", 1)

	err = sendEmail(url)
	if err != nil {
		log.Printf("send email failed: %v", url)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	err = dbUpdateMailStatus(cred.Email)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func sendEmail(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("could not update DB as status from email server: %v %v", resp.Status, resp.StatusCode)
	}
	return nil
}

func login(w http.ResponseWriter, r *http.Request) {
	var cred Credentials
	err := json.NewDecoder(r.Body).Decode(&cred)
	if err != nil {
		log.Printf("JSON, login err %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	result, err := dbSelect(cred.Email)
	if err != nil {
		log.Printf("DB select, %v err %v", cred.Email, err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if result.activated.Unix() == 0 {
		log.Printf("user %v is not activated failed: %v", cred.Email, err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	dk, err := scrypt.Key([]byte(cred.Password), result.salt, 32768, 8, 1, 32)
	if bytes.Compare(dk, result.password) != 0 {
		w.WriteHeader(http.StatusUnauthorized)
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
	lang := vars["lang"]

	fmt.Printf("go to URL: http://%s/confirm/%s/%s/%s", r.Host, email, token, lang)
	r.Body.Close()
	w.WriteHeader(http.StatusOK)
}

func main() {
	var opts Opts
	_, err := flags.NewParser(&opts, flags.None).Parse()
	if err != nil {
		log.Fatal(err)
	}
	exp = time.Hour * 24 * time.Duration(opts.Expires)

	_, doneChannel := server(&opts)
	select {
	case <-doneChannel:
		log.Printf("Done")
	}

}

func server(opts *Opts) (*http.Server, <-chan bool) {
	options = opts
	var err error
	db, err = sql.Open("sqlite3", options.DBPath+"/ffs.db")
	if err != nil {
		log.Fatal(err)
	}

	r := mux.NewRouter()
	r.HandleFunc("/login", login).Methods("POST")
	r.HandleFunc("/signin", signin).Methods("POST")
	r.HandleFunc("/confirm/{email}/{token}/{lang}", confirm).Methods("GET")
	r.HandleFunc("/refresh", auth(refresh)).Methods("GET")
	r.HandleFunc("/send/{email}/{token}/{lang}", send).Methods("GET")

	//this will create or alter tables
	file, err := ioutil.ReadFile("startup.sql")
	if err != nil {
		log.Fatal(err)
	}

	requests := strings.Split(string(file), ";")
	for _, request := range requests {
		request = strings.Replace(request, "\n", "", -1)
		request = strings.Replace(request, "\t", "", -1)
		_, err = db.Exec(request)
		if err != nil {
			log.Fatalf("[%v] %v", request, err)
		}
	}

	log.Printf("Starting auth server on port %v...", opts.Port)
	s := http.Server{Addr: ":" + strconv.Itoa(opts.Port), Handler: r}

	doneChannel := make(chan bool)
	go func() {
		if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
		log.Printf("Finished")
		defer db.Close()
		doneChannel <- true
	}()
	return &s, doneChannel
}

func genRnd(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}
