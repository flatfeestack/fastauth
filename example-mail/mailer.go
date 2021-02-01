package main

import (
	"encoding/base32"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/domodwyer/mailyak/v3"
	"github.com/joho/godotenv"
	"gopkg.in/square/go-jose.v2/jwt"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"
)

/*
Test with:

curl -k -X POST -H "Authorization: Bearer ${TOKEN}" -H "Content-Type: application/json" -d '{"subject":"hàallo","text_message":"Ello","html_message":"<!doctype html><html><body><h1>Ello</h1></body></html>"}' http://localhost:8091

*/

type TokenClaims struct {
	MailFrom string `json:"mail_from,omitempty"`
	MailTo   string `json:"mail_to,omitempty"`
	jwt.Claims
}

type Opts struct {
	Env          string
	HS256        string
	Port         int
	SmtpPassword string
	SmtpHost     string
	SmtpPort     int
}

var (
	opts   *Opts
	jwtKey []byte
	debug  = false
)

type EmailRequest struct {
	MailTo      string `json:"mail_to,omitempty"`
	Subject     string `json:"subject"`
	TextMessage string `json:"text_message"`
	HtmlMessage string `json:"html_message"`
}

func mailer(w http.ResponseWriter, r *http.Request, claims *TokenClaims) {
	if r.Method != "POST" {
		writeErr(w, http.StatusBadRequest, "ERR-07, only POST supported: %v", r.Method)
		return
	}

	var email EmailRequest
	err := json.NewDecoder(r.Body).Decode(&email)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ERR-08, could not decode request: %v", err)
		return
	}

	mail := mailyak.New(opts.SmtpHost+":"+strconv.Itoa(opts.SmtpPort), smtp.PlainAuth("", claims.MailFrom, opts.SmtpPassword, opts.SmtpHost))
	var to string
	if claims.MailTo != "" {
		to = claims.MailTo
	} else {
		to = email.MailTo
	}
	mail.To(to)
	mail.From(claims.MailFrom)
	mail.Subject(email.Subject)
	if email.TextMessage != "" {
		mail.Plain().Set(email.TextMessage)
	}
	if email.HtmlMessage != "" {
		mail.HTML().Set(email.HtmlMessage)
	}

	err = mail.Send()
	if err != nil {
		writeErr(w, http.StatusBadRequest, "ERR-09, could not send email: %v", err)
		return
	}
	log.Printf("Email sent from [%s] to [%v], subject: [%v]\n", claims.MailFrom, to, email.Subject)
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
	flag.StringVar(&opts.Env, "env", lookupEnv("ENV"), "ENV variable")
	flag.StringVar(&opts.HS256, "hs256", lookupEnv("HS256"), "HS256 key")
	flag.IntVar(&opts.Port, "port", lookupEnvInt("PORT"), "Listening port")
	flag.StringVar(&opts.SmtpPassword, "smtp-pw", lookupEnv("SMTP-PW"), "Password for the mail server")
	flag.IntVar(&opts.SmtpPort, "smtp-port", lookupEnvInt("SMTP-PORT", 587), "Port of the mailserver")
	flag.StringVar(&opts.SmtpHost, "smtp-host", lookupEnv("SMTP-HOST"), "Host of the mailserver")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	//defaults
	if opts.HS256 != "" {
		jwtKey, err = base32.StdEncoding.DecodeString(opts.HS256)
		if err != nil {
			log.Fatalf("cannot decode %v", opts.HS256)
		}
	}

	if opts.Env == "local" || opts.Env == "dev" {
		debug = true
	}

	return opts
}

func main() {
	opts = NewOpts()

	http.HandleFunc("/", jwtAuth(mailer))
	log.Printf("listening on port %v...", opts.Port)
	http.ListenAndServe(":"+strconv.Itoa(opts.Port), nil)
}
