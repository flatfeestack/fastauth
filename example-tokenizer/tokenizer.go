package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base32"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"golang.org/x/crypto/ed25519"
	"log"
	"os"
	"strings"
)

/*
Create token for the file-upload:
./tokenizer -hs256=true -sub="tom" -map=dir:/var/www

Create token for the mailer:
./tokenizer -hs256=true -sub="tom" -map="mail_from:no-reply@flatfeestack.io" -map="mail_to:tom@bocek.ch"
*/

type Opts struct {
	HS256   string
	RS256   string
	EdDSA   string
	Subject string
	Dir     string
}

var (
	options      *Opts
	jwtKey       []byte
	privRSA      *rsa.PrivateKey
	privRSAKid   string
	privEdDSA    *ed25519.PrivateKey
	privEdDSAKid string
	tokenClaims  = mapClaims{}
)

type mapClaims map[string]interface{}

func (m *mapClaims) String() string {
	return "my string representation"
}

func (m *mapClaims) Set(value string) error {
	kv := strings.Split(value, ":")
	if len(kv) != 2 {
		return fmt.Errorf("could not split string [%v], separator : not found", value)
	}
	tmp := *m
	tmp[kv[0]] = kv[1]
	return nil
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

func NewOpts() *Opts {
	opts := &Opts{}
	flag.StringVar(&opts.HS256, "hs256", lookupEnv("HS256"), "HS256 key, set to true to generate a key")
	flag.StringVar(&opts.RS256, "rs256", lookupEnv("RS256"), "RS256 key, set to true to generate a key")
	flag.StringVar(&opts.EdDSA, "eddsa", lookupEnv("EDDSA"), "EdDSA key, set to true to generate a key")
	flag.StringVar(&opts.Subject, "sub", lookupEnv("SUB"), "Subject name how can upload")
	flag.Var(&tokenClaims, "map", "Set key values, separated by : to set other values in the token.")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	//defaults
	var err error
	if opts.HS256 != "" {
		if opts.HS256 == "true" {
			jwtKey, err = genRnd(32)
			if err != nil {
				log.Fatalf("cannot decode %v", opts.HS256)
			}
		} else {
			jwtKey, err = base32.StdEncoding.DecodeString(opts.HS256)
			if err != nil {
				log.Fatalf("cannot decode %v", opts.HS256)
			}
		}
		log.Printf("HS256 key [%s]", base32.StdEncoding.EncodeToString(jwtKey))
	}

	if opts.RS256 != "" {
		if opts.RS256 == "true" {
			privRSA, err = rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				log.Fatalf("cannot decode %v", opts.RS256)
			}
		} else {
			rsaDec, err := base32.StdEncoding.DecodeString(opts.RS256)
			if err != nil {
				log.Fatalf("cannot decode %v", opts.RS256)
			}
			i, err := x509.ParsePKCS8PrivateKey(rsaDec)
			if err != nil {
				log.Fatalf("cannot decode %v", rsaDec)
			}
			privRSA = i.(*rsa.PrivateKey)
		}

		k := jose.JSONWebKey{Key: privRSA.Public()}
		kid, err := k.Thumbprint(crypto.SHA256)
		if err != nil {
			log.Fatalf("cannot decode %v", err)
		}
		privRSAKid = hex.EncodeToString(kid)
		b, err := x509.MarshalPKCS8PrivateKey(privRSA)
		if err != nil {
			log.Fatalf("cannot decode %v", err)
		}
		log.Printf("RS256 key [%s]", base32.StdEncoding.EncodeToString(b))
	}

	if opts.EdDSA != "" {
		if opts.EdDSA == "true" {
			_, *privEdDSA, err = ed25519.GenerateKey(rand.Reader)
		} else {
			eddsa, err := base32.StdEncoding.DecodeString(opts.EdDSA)
			if err != nil {
				log.Fatalf("cannot decode %v", opts.EdDSA)
			}
			privEdDSA0 := ed25519.PrivateKey(eddsa)
			privEdDSA = &privEdDSA0
		}
		k := jose.JSONWebKey{Key: privEdDSA.Public()}
		kid, err := k.Thumbprint(crypto.SHA256)
		if err != nil {
			log.Fatalf("cannot decode %v", opts.EdDSA)
		}
		privEdDSAKid = hex.EncodeToString(kid)
		log.Printf("EdDSA key [%s]", base32.StdEncoding.EncodeToString(*privEdDSA))
	}

	if jwtKey == nil && privEdDSA == nil && privRSA == nil {
		flag.PrintDefaults()
		log.Fatal("Need at least one key, set a key to true to generate one")
	}

	return opts
}

func encodeAccessToken(dir string, subject string) (string, error) {
	var sig jose.Signer
	var err error
	if jwtKey != nil {
		sig, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: jwtKey}, (&jose.SignerOptions{}).WithType("JWT"))
	} else if privRSA != nil {
		sig, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privRSA}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", privRSAKid))
	} else if privEdDSA != nil {
		sig, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: privEdDSA}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", privEdDSAKid))
	} else {
		return "", fmt.Errorf("JWT access token %v no keys", subject)
	}

	tokenClaims["sub"] = subject
	accessTokenString, err := jwt.Signed(sig).Claims(map[string]interface{}(tokenClaims)).CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("JWT access token %v failed: %v", subject, err)
	}
	return accessTokenString, nil
}

type TokenClaims struct {
	Directory string `json:"dir,omitempty"`
	jwt.Claims
}

func main() {
	opts := NewOpts()

	token, err := encodeAccessToken(opts.Dir, opts.Subject)
	if err != nil {
		log.Fatalf("Cannot create token %v", err)
	}
	log.Printf("Token for %v, subject: %v\n[%v]\n", tokenClaims, opts.Subject, token)
}
