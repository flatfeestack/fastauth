package main

/*
curl upload command:

curl -H "Authorization: Bearer ${TOKEN}" -X POST -F 'upload=@test.tar.gz' -k http://localhost:8080

*/

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base32"
	"flag"
	"fmt"
	"golang.org/x/crypto/ed25519"
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
	options   *Opts
	jwtKey    []byte
	privRSA   *rsa.PrivateKey
	privEdDSA *ed25519.PrivateKey
	Debug     = true
)

func uploadFile(w http.ResponseWriter, r *http.Request, claims *TokenClaims) {
	//upload size
	err := r.ParseMultipartForm(1 << 24) // 16MB limit for the file
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ERR-01, cannot parse file: %v", err)
		return
	}

	//reading original file
	file, _, err := r.FormFile("upload")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ERR-02, error retrieving the file: %v", err)
		return
	}
	defer file.Close()

	err = Untar(file, options.Basedir+"/"+claims.Directory)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ERR-03, error untaring the file: %v", err)
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

		if tok.Headers[0].Algorithm == string(jose.RS256) {
			err = tok.Claims(privRSA.Public(), claims)
		} else if tok.Headers[0].Algorithm == string(jose.HS256) {
			err = tok.Claims(jwtKey, claims)
		} else if tok.Headers[0].Algorithm == string(jose.EdDSA) {
			err = tok.Claims(privEdDSA.Public(), claims)
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
	if Debug {
		w.Write([]byte(`{"error":"` + msg + `"}`))
	}
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
