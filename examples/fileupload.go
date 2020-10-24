package main

/*
curl upload command:

curl -H "Authorization: Bearer ${TOKEN}" -X POST -F 'upload=@test.tar.gz' -k http://localhost:8080

*/

import (
	"crypto/rand"
	"encoding/base32"
	"flag"
	"fmt"
	"gopkg.in/square/go-jose.v2"
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
	HS256   string
	Basedir string
	Name    string
	Reldir  string
	Port    int
}

var (
	options *Opts
	jwtKey  []byte
)

func uploadFile(w http.ResponseWriter, r *http.Request, claims *TokenClaims) {
	//upload size
	err := r.ParseMultipartForm(1 << 24) // 16MB limit for the file
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "ERR-01, cannot parse file: %v", err)
		return
	}

	//reading original file
	file, _, err := r.FormFile("upload")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "ERR-02, error retrieving the file: %v", err)
		return
	}
	defer file.Close()

	err = Untar(file, options.Basedir+"/"+claims.Directory)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "ERR-03, error untaring the file: %v", err)
		return
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
					writeErr(w, http.StatusBadRequest, "invalid_request", "ERR-04, could not parse token: %v", bearerToken[1])
					return
				}

				claims := &TokenClaims{}

				if tok.Headers[0].Algorithm == string(jose.HS256) {
					err = tok.Claims(jwtKey, claims)
				} else {
					writeErr(w, http.StatusUnauthorized, "invalid_client", "ERR-05, could not parse claims: %v", bearerToken[1])
					return
				}

				if err != nil {
					writeErr(w, http.StatusUnauthorized, "invalid_client", "ERR-06, could not parse claims: %v", bearerToken[1])
					return
				}

				if claims.Expiry != nil && !claims.Expiry.Time().After(time.Now()) {
					writeErr(w, http.StatusBadRequest, "invalid_client", "ERR-07, expired: %v", bearerToken[1])
					return
				}

				next(w, r, claims)
				return
			} else {
				writeErr(w, http.StatusBadRequest, "invalid_request", "ERR-08, could not split token: %v", bearerToken)
				return
			}
		}
		writeErr(w, http.StatusBadRequest, "invalid_request", "ERR-09, authorization header not set")
		return
	}
}

func writeErr(w http.ResponseWriter, code int, error string, format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	log.Printf(msg)
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(code)
	w.Write([]byte(`{"error":"` + error + `","error_uri":"https://host:port/error-descriptions/authorization-request/` + error + `"}`))
}

func encodeAccessToken(dir string, subject string) (string, error) {
	tokenClaims := &TokenClaims{
		Directory: dir,
		Claims: jwt.Claims{
			Subject: subject,
		},
	}
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: jwtKey}, (&jose.SignerOptions{}).WithType("JWT"))

	if err != nil {
		return "", fmt.Errorf("JWT access token %v failed: %v", tokenClaims.Subject, err)
	}
	accessTokenString, err := jwt.Signed(sig).Claims(tokenClaims).CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("JWT access token %v failed: %v", tokenClaims.Subject, err)
	}
	return accessTokenString, nil
}

func NewOpts() *Opts {
	opts := &Opts{}
	flag.StringVar(&opts.HS256, "hs256", LookupEnv("HS256"), "HS256 key")
	flag.IntVar(&opts.Port, "port", LookupEnvInt("PORT"), "Listening port")
	flag.StringVar(&opts.Basedir, "base", LookupEnv("BASE"), "Base directory")
	flag.StringVar(&opts.Reldir, "rel", LookupEnv("REL"), "Relative directory")
	flag.StringVar(&opts.Name, "name", LookupEnv("NAME"), "Subject name")
	flag.Parse()
	return opts
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

func defaultOpts(opts *Opts) {
	var err error
	if opts.HS256 != "" {
		jwtKey, err = base32.StdEncoding.DecodeString(opts.HS256)
		if err != nil {
			log.Fatalf("cannot decode %v", opts.HS256)
		}
	} else {
		jwtKey, err = genRnd(32)
		if err != nil {
			log.Fatalf("cannot decode %v", opts.HS256)
		}
	}
	log.Printf("using key [%s]", base32.StdEncoding.EncodeToString(jwtKey))

	opts.Basedir = setDefault(opts.Basedir, os.TempDir())

	if opts.Port == 0 {
		if opts.Reldir == "" || opts.Name == "" {
			log.Fatalf("need reldir")
		}
		token, err := encodeAccessToken(opts.Reldir, opts.Name)
		if err != nil {
			log.Fatalf("cannot decode %v", opts.HS256)
		}
		log.Printf("access token: [%s]", token)

	}
}

func main() {
	options = NewOpts()
	defaultOpts(options)
	if options.Port > 0 {
		log.Printf("listening on port %v...", options.Port)
		http.HandleFunc("/", jwtAuth(uploadFile))
		http.ListenAndServe(":"+strconv.Itoa(options.Port), nil)
	}
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
