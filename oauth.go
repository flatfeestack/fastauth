package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/gorilla/mux"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

func oauth(w http.ResponseWriter, r *http.Request) {
	grantType := param("grant_type", r)
	if grantType == "refresh_token" {
		err := basic(w, r)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-oauth-01, basic auth failed")
			return
		}
		refreshToken := param("refresh_token", r)
		if refreshToken == "" {
			writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-oauth-02, no refresh token")
			return
		}

		accessToken, refreshToken, expiresAt, err := refresh0(refreshToken)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_grant", "blocked", "ERR-oauth-03, cannot verify refresh token %v", err)
			return
		}
		w.Write([]byte(`{"access_token":"` + accessToken + `",` +
			`"token_type":"Bearer",` +
			`"refresh_token":"` + refreshToken + `",` +
			`"expires_in":` + strconv.FormatInt(expiresAt, 10) + `}`))

	} else if grantType == "password" {
		err := basic(w, r)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-oauth-04, basic auth failed")
			return
		}
		email := param("username", r)
		password := param("password", r)
		scope := param("scope", r)
		if email == "" || password == "" || scope == "" {
			writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-oauth-05, username, password, or scope empty")
			return
		}

		result, errString, err := checkEmailPassword(email, password)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_grant", errString, "ERR-oauth-06 %v", err)
			return
		}

		retVal, err := createBearer(email, result)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-oauth-07, cannot set access token for %v, %v", email, err)
			return
		}

		w.Write([]byte(retVal))

	} else if grantType == "authorization_code" {
		err := basic(w, r)
		if err != nil {
			clientId := param("client_id", r)
			clientSecret := param("client_secret", r)
			if clientId != options.OAuthUser || clientSecret != options.OAuthPass {
				writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-oauth-04, basic auth failed")
				return
			}
		}

		code := param("code", r)
		codeVerifier := param("code_verifier", r)
		cc, err := checkCodeToken(code)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-oauth-04, basic auth failed")
			return
		}
		if cc.CodeCodeChallengeMethod == "S256" {
			h := sha256.Sum256([]byte(codeVerifier))
			s := base64.URLEncoding.EncodeToString(h[:])
			if cc.CodeChallenge != s {
				writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-oauth-04, auth challenge failed")
				return
			}
		}

		result, err := dbSelect(cc.Subject)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_grant", "not-found", "ERR-oauth-06 %v", err)
			return
		}

		retVal, err := createBearer(cc.Subject, result)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-oauth-07, cannot set access token for %v, %v", cc.Subject, err)
			return
		}

		w.Write([]byte(retVal))

	} else {
		writeErr(w, http.StatusBadRequest, "unsupported_grant_type", "blocked", "ERR-oauth-07, unsupported grant type")
		return
	}
}

func checkCodeToken(token string) (*CodeClaims, error) {
	tok, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, fmt.Errorf("ERR-check-refresh-01, could not check sig %v", err)
	}
	codeClaims := &CodeClaims{}
	if tok.Headers[0].Algorithm == string(jose.RS256) {
		err := tok.Claims(privRSA.Public(), codeClaims)
		if err != nil {
			return nil, fmt.Errorf("ERR-check-refresh-02, could not parse claims %v", err)
		}
	} else if tok.Headers[0].Algorithm == string(jose.HS256) {
		err := tok.Claims(jwtKey, codeClaims)
		if err != nil {
			return nil, fmt.Errorf("ERR-check-refresh-03, could not parse claims %v", err)
		}
	} else if tok.Headers[0].Algorithm == string(jose.EdDSA) {
		err := tok.Claims(privEdDSA.Public(), codeClaims)
		if err != nil {
			return nil, fmt.Errorf("ERR-check-refresh-04, could not parse claims %v", err)
		}
	} else {
		return nil, fmt.Errorf("ERR-check-refresh-05, could not parse claims, no algo found %v", tok.Headers[0].Algorithm)
	}
	t := time.Unix(codeClaims.ExpiresAt, 0)
	if !t.After(time.Now()) {
		return nil, fmt.Errorf("ERR-check-refresh-06, expired %v", err)
	}
	return codeClaims, nil
}

func createBearer(email string, result *dbRes) (string, error) {
	encodedAccessToken, err := encodeAccessToken(string(result.role), email)
	if err != nil {
		return "", fmt.Errorf("ERR-oauth-07, cannot set access token for %v, %v", email, err)
	}

	refreshToken := *result.refreshToken
	if options.ResetRefresh {
		refreshToken, err = resetRefreshToken(refreshToken)
		if err != nil {
			return "", fmt.Errorf("ERR-oauth-08, cannot reset access token for %v, %v", email, err)
		}
	}
	encodedRefreshToken, expiresAt, err := encodeRefreshToken(email, refreshToken)
	if err != nil {
		return "", fmt.Errorf("ERR-oauth-09, cannot set refresh token for %v, %v", email, err)
	}

	return `{"access_token":"` + encodedAccessToken + `",` +
		`"token_type":"Bearer",` +
		`"refresh_token":"` + encodedRefreshToken + `",` +
		`"expires_in":` + strconv.FormatInt(expiresAt, 10) + `}`, nil
}

//https://tools.ietf.org/html/rfc6749#section-1.3.1
//https://developer.okta.com/blog/2019/08/22/okta-authjs-pkce
func authorize(w http.ResponseWriter, r *http.Request) {
	grantType := param("grant_type", r)
	if grantType == "authorization_code" {
		err := basic(w, r)
		if err != nil {
			clientId := param("client_id", r)
			clientSecret := param("client_secret", r)
			if clientId != options.OAuthUser || clientSecret != options.OAuthPass {
				writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-oauth-04, basic auth failed")
				return
			}
		}
		email := param("username", r)
		password := param("password", r)
		codeChallenge := param("code_challenge", r)
		codeChallengeMethod := param("code_challenge_method", r)
		state := param("state", r)
		//redirectUri := param("redirect_uri", r)
		//scope := param("scope", r)

		if email == "" || password == "" {
			writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-oauth-05, username, password empty")
			return
		}

		_, errString, err := checkEmailPassword(email, password)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_grant", errString, "ERR-oauth-06 %v", err)
			return
		}

		encodedCodeToken, expiresAt, err := encodeCodeToken(email, codeChallenge, codeChallengeMethod)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_grant", "blocked", "ERR-oauth-06 %v", err)
			return
		}

		w.Write([]byte(`{"code":"` + encodedCodeToken + `",
				"state":"` + state + `",
				"expires_in":` + strconv.FormatInt(expiresAt, 10) + `}`))
	} else {
		writeErr(w, http.StatusBadRequest, "unsupported_grant_type", "blocked", "ERR-oauth-07, unsupported grant type")
		return
	}
}

func revoke(w http.ResponseWriter, r *http.Request) {
	tokenHint := param("token_type_hint", r)
	if tokenHint == "refresh_token" {
		oldToken := param("token", r)
		if oldToken == "" {
			writeErr(w, http.StatusBadRequest, "unsupported_grant_type1", "blocked", "ERR-oauth-07, unsupported grant type")
			return
		}
		_, err := resetRefreshToken(oldToken)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "unsupported_grant_type2", "blocked", "ERR-oauth-07, unsupported grant type")
			return
		}
	} else {
		writeErr(w, http.StatusBadRequest, "unsupported_grant_type", "blocked", "ERR-oauth-07, unsupported grant type")
		return
	}
}

func basicAuth(next func(w http.ResponseWriter, r *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if options.OAuthUser != "" || options.OAuthPass != "" {
			user, pass, ok := r.BasicAuth()
			if !ok || user != options.OAuthUser || pass != options.OAuthPass {
				writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-basic-auth-01, could not check user/pass: %v", user)
				return
			}
		}
		next(w, r)
	}
}

func basic(w http.ResponseWriter, r *http.Request) error {
	if options.OAuthUser != "" || options.OAuthPass != "" {
		user, pass, ok := r.BasicAuth()
		if !ok || user != options.OAuthUser || pass != options.OAuthPass {
			return fmt.Errorf("ERR-basic-auth-01, could not check user/pass: %v", user)
		}
	}
	return nil
}

func param(name string, r *http.Request) string {
	n1 := mux.Vars(r)[name]
	n2, _ := url.QueryUnescape(r.URL.Query().Get(name))
	n3 := r.FormValue(name)

	if n1 == "" {
		if n2 == "" {
			return n3
		}
		return n2
	}
	return n1
}
