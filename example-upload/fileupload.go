package main

/*
curl upload command:

Testing with:
curl -k -H "Authorization: Bearer ${TOKEN}" -X POST -F 'upload=@test.tar.gz' http://localhost:8080

Production with:
curl -H "Authorization: Bearer ${TOKEN}" -X POST -F 'upload=@test.tar.gz' https://domain

*/

import (
	"encoding/base32"
	"flag"
	"fmt"
	"github.com/joho/godotenv"
	"gopkg.in/square/go-jose.v2/jwt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type TokenClaims struct {
	Directory string `json:"dir,omitempty"`
	jwt.Claims
}

type Opts struct {
	Env     string
	HS256   string
	Basedir string
	Port    int
}

var (
	options *Opts
	jwtKey  []byte
	debug   = false
)

func uploadFile(w http.ResponseWriter, r *http.Request, claims *TokenClaims) {
	if r.Method != "POST" {
		writeErr(w, http.StatusBadRequest, "ERR-01, only POST supported: %v", r.Method)
		return
	}

	//upload size
	err := r.ParseMultipartForm(1 << 29) // 512MB limit for the file
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ERR-02, cannot parse file: %v", err)
		return
	}

	//reading original file
	file, _, err := r.FormFile("upload")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ERR-03, error retrieving the file: %v", err)
		return
	}
	defer file.Close()

	log.Printf("upload file %v to: %v", file, options.Basedir+"/"+claims.Directory)
	err = Untar(file, options.Basedir+"/"+claims.Directory)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ERR-04, error untaring the file: %v", err)
		return
	}
}

func jwtAuth(next func(w http.ResponseWriter, r *http.Request, claims *TokenClaims)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeErr(w, http.StatusBadRequest, "ERR-01, authorization header not set")
			return
		}

		bearerToken := strings.Split(authHeader, " ")
		if len(bearerToken) != 2 {
			writeErr(w, http.StatusBadRequest, "ERR-02, could not split token: %v", bearerToken)
			return
		}

		tok, err := jwt.ParseSigned(bearerToken[1])
		if err != nil {
			writeErr(w, http.StatusBadRequest, "ERR-03, could not parse token: %v", bearerToken[1])
			return
		}

		claims := &TokenClaims{}

		if tok.Headers[0].Algorithm == "HS256" {
			err = tok.Claims(jwtKey, claims)
		} else {
			writeErr(w, http.StatusUnauthorized, "ERR-04, unknown algorithm: %v", tok.Headers[0].Algorithm)
			return
		}

		if err != nil {
			writeErr(w, http.StatusUnauthorized, "ERR-05, could not parse claims: %v", bearerToken[1])
			return
		}

		if claims.Expiry != nil && !claims.Expiry.Time().After(time.Now()) {
			writeErr(w, http.StatusBadRequest, "ERR-06, expired: %v", claims.Expiry.Time())
			return
		}

		next(w, r, claims)
	}
}

func writeErr(w http.ResponseWriter, code int, format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	log.Printf(msg)
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(code)
	if debug {
		w.Write([]byte(`{"error":"` + msg + `"}`))
	}
}

func NewOpts() *Opts {
	err := godotenv.Load()
	if err != nil {
		log.Printf("Could not find env file [%v], using defaults", err)
	}
	err = nil

	opts := &Opts{}
	flag.StringVar(&opts.Env, "env", lookupEnv("ENV"), "ENV variable")
	flag.StringVar(&opts.HS256, "hs256", lookupEnv("HS256"), "HS256 key")
	flag.IntVar(&opts.Port, "port", lookupEnvInt("PORT"), "Listening port")
	flag.StringVar(&opts.Basedir, "base", lookupEnv("BASE", os.TempDir()), "Base directory")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	//defaults
	if opts.HS256 != "" {
		if strings.Index(opts.HS256, "0x") == 0 {
			jwtKey, err = base32.StdEncoding.DecodeString(opts.HS256[2:])
		} else {
			jwtKey = []byte(opts.HS256)
		}
		if err != nil {
			log.Fatalf("cannot decode %v", opts.HS256)
		}
	}

	if opts.Env == "local" || opts.Env == "dev" {
		debug = true
	}

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

func main() {
	options = NewOpts()

	http.HandleFunc("/", jwtAuth(uploadFile))
	log.Printf("listening on port %v...", options.Port)
	http.ListenAndServe(":"+strconv.Itoa(options.Port), nil)
}
