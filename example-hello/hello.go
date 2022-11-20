package main

import (
	"flag"
	"fmt"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/joho/godotenv"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type Opts struct {
	Env   string
	HS256 string
	Port  int
}

var (
	opts   *Opts
	jwtKey []byte
	debug  = false
)

/*
curl -H "Authorization: Bearer ${TOKEN}" http://localhost:8080
*/

func hello(w http.ResponseWriter, r *http.Request, claims *jwt.Claims) {
	log.Printf("All good!")
	w.WriteHeader(http.StatusOK)
}

func jwtAuth(next func(w http.ResponseWriter, r *http.Request, claims *jwt.Claims)) func(http.ResponseWriter, *http.Request) {
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

		claims := &jwt.Claims{}

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

func NewOpts() *Opts {
	err := godotenv.Load()
	if err != nil {
		log.Printf("Could not find env file [%v], using defaults", err)
	}

	opts := &Opts{}
	flag.StringVar(&opts.Env, "env", lookupEnv("ENV", "local"), "ENV variable")
	flag.StringVar(&opts.HS256, "hs256", lookupEnv("HS256"), "HS256 key")
	flag.IntVar(&opts.Port, "port", lookupEnvInt("PORT", 8080), "Listening port")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	//defaults
	if opts.HS256 != "" {
		//jwtKey, err = base32.StdEncoding.DecodeString(opts.HS256)
		//if err != nil {
		//	log.Fatalf("cannot decode %v", opts.HS256)
		//}
		jwtKey = []byte(opts.HS256)
	}

	if opts.Env == "local" || opts.Env == "dev" {
		debug = true
	}

	return opts
}

func main() {
	opts = NewOpts()

	http.HandleFunc("/", jwtAuth(hello))
	log.Printf("listening on port %v...", opts.Port)
	http.ListenAndServe(":"+strconv.Itoa(opts.Port), nil)
}
