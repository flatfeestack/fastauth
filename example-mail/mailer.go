package main

import (
	"encoding/base32"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/domodwyer/mailyak/v3"
	"github.com/joho/godotenv"
	log "github.com/sirupsen/logrus"
	"gopkg.in/square/go-jose.v2/jwt"
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

var (
	opts   *Opts
	jwtKey []byte
	debug  = false
	queue  chan *EmailRequest
)

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
	Parallel     int
}

type EmailRequest struct {
	MailTo      string `json:"mail_to,omitempty"`
	Subject     string `json:"subject"`
	TextMessage string `json:"text_message"`
	HtmlMessage string `json:"html_message"`
	claims      *TokenClaims
}

func mailer(w http.ResponseWriter, r *http.Request, claims *TokenClaims) {
	if r.Method != "POST" {
		writeErr(w, http.StatusBadRequest, "mailer, only POST supported: %v", r.Method)
		return
	}

	var email EmailRequest
	err := json.NewDecoder(r.Body).Decode(&email)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "mailer, could not decode request: %v", err)
		return
	}
	email.claims = claims
	queue <- &email
}

func jwtAuth(next func(w http.ResponseWriter, r *http.Request, claims *TokenClaims)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeErr(w, http.StatusBadRequest, "jwtAuth, authorization header not set")
			return
		}

		bearerToken := strings.Split(authHeader, " ")
		if len(bearerToken) != 2 {
			writeErr(w, http.StatusBadRequest, "jwtAuth, could not split token: %v", bearerToken)
			return
		}

		tok, err := jwt.ParseSigned(bearerToken[1])
		if err != nil {
			writeErr(w, http.StatusBadRequest, "jwtAuth, could not parse token: %v", bearerToken[1])
			return
		}

		claims := &TokenClaims{}

		if tok.Headers[0].Algorithm == "HS256" {
			err = tok.Claims(jwtKey, claims)
		} else {
			writeErr(w, http.StatusUnauthorized, "jwtAuth, unknown algorithm: %v", tok.Headers[0].Algorithm)
			return
		}

		if err != nil {
			writeErr(w, http.StatusUnauthorized, "jwtAuth, could not parse claims: %v", bearerToken[1])
			return
		}

		if claims.Expiry != nil && !claims.Expiry.Time().After(time.Now()) {
			writeErr(w, http.StatusBadRequest, "jwtAuth, expired: %v", claims.Expiry.Time())
			return
		}

		next(w, r, claims)
	}
}

func writeErr(w http.ResponseWriter, code int, format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	log.Warnf(msg)
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
	flag.IntVar(&opts.Parallel, "parallel", lookupEnvInt("PARALLEL", 4), "How many email should be send in parallel")
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

	//create a queue, and send one after the other
	queue = make(chan *EmailRequest)
	for i := 0; i < opts.Parallel; i++ {
		go func() {
			for {
				select {
				case e := <-queue:
					send(e)
				}
			}
		}()
	}

	http.ListenAndServe(":"+strconv.Itoa(opts.Port), nil)
}

func send(e *EmailRequest) {
	mail := mailyak.New(opts.SmtpHost+":"+strconv.Itoa(opts.SmtpPort), smtp.PlainAuth("", e.claims.MailFrom, opts.SmtpPassword, opts.SmtpHost))
	var to string
	if e.claims.MailTo != "" {
		to = e.claims.MailTo
	} else {
		to = e.MailTo
	}
	mail.To(to)
	mail.From(e.claims.MailFrom)
	mail.Subject(e.Subject)
	if e.TextMessage != "" {
		mail.Plain().Set(e.TextMessage)
	}
	if e.HtmlMessage != "" {
		mail.HTML().Set(e.HtmlMessage)
	}

	err := mail.Send()
	if err != nil {
		log.Warnf("could not send email: %v", err)
	} else {
		log.Infof("Email sent from [%s] to [%v], subject: [%v]\n", e.claims.MailFrom, to, e.Subject)
	}
}
