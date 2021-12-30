package main

import (
	"encoding/json"
	"fmt"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"log"
	"net/http"
	"strings"
	"time"
)

func jwtAuthAdmin(next func(w http.ResponseWriter, r *http.Request, email string), emails []string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, err := jwtAuth0(r)
		if claims != nil && err != nil {
			writeErr(w, http.StatusUnauthorized, "invalid_client", "refused", "Token expired: %v, available: %v", claims.Subject, emails)
			return
		} else if claims == nil && err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "jwtAuthAdmin error: %v", err)
			return
		}
		for _, email := range emails {
			if claims.Subject == email {
				log.Printf("Authenticated admin %s\n", email)
				next(w, r, email)
				return
			}
		}
		writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "ERR-01,jwtAuthAdmin error: %v != %v", claims.Subject, emails)
	}
}

func jwtAuth(next func(w http.ResponseWriter, r *http.Request, claims *TokenClaims)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, err := jwtAuth0(r)
		if claims != nil && err != nil {
			writeErr(w, http.StatusUnauthorized, "invalid_client", "refused", "Token expired: %v", claims.Subject)
			return
		} else if claims == nil && err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "blocked", "jwtAuthAdmin error: %v", err)
			return
		}
		next(w, r, claims)
	}
}

func jwtAuth0(r *http.Request) (*TokenClaims, error) {
	authHeader := r.Header.Get("Authorization")
	split := strings.Split(authHeader, " ")
	if len(split) != 2 {
		return nil, fmt.Errorf("ERR-02, could not split token, auth header is: [%v]", authHeader)
	}
	bearerToken := split[1]

	tok, err := jwt.ParseSigned(bearerToken)
	if err != nil {
		return nil, fmt.Errorf("ERR-03, could not parse token: %v", bearerToken[1])
	}

	claims := &TokenClaims{}

	if tok.Headers[0].Algorithm == string(jose.RS256) {
		err = tok.Claims(privRSA.Public(), claims)
	} else if tok.Headers[0].Algorithm == string(jose.HS256) {
		err = tok.Claims(jwtKey, claims)
	} else if tok.Headers[0].Algorithm == string(jose.EdDSA) {
		err = tok.Claims(privEdDSA.Public(), claims)
	} else {
		return nil, fmt.Errorf("ERR-04, unknown algorithm: %v", tok.Headers[0].Algorithm)
	}

	if err != nil {
		return nil, fmt.Errorf("ERR-05, could not parse claims: %v", bearerToken)
	}

	if claims.Expiry != nil && !claims.Expiry.Time().After(timeNow()) {
		return claims, fmt.Errorf("ERR-06, unauthorized: %v", bearerToken)
	}

	if claims.Subject == "" {
		return nil, fmt.Errorf("ERR-07, no subject: %v", claims)
	}
	return claims, nil
}

func checkRefreshToken(token string) (*RefreshClaims, error) {
	tok, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, fmt.Errorf("ERR-check-refresh-01, could not check sig %v", err)
	}
	refreshClaims := &RefreshClaims{}
	if tok.Headers[0].Algorithm == string(jose.RS256) {
		err := tok.Claims(privRSA.Public(), refreshClaims)
		if err != nil {
			return nil, fmt.Errorf("ERR-check-refresh-02, could not parse claims %v", err)
		}
	} else if tok.Headers[0].Algorithm == string(jose.HS256) {
		err := tok.Claims(jwtKey, refreshClaims)
		if err != nil {
			return nil, fmt.Errorf("ERR-check-refresh-03, could not parse claims %v", err)
		}
	} else if tok.Headers[0].Algorithm == string(jose.EdDSA) {
		err := tok.Claims(privEdDSA.Public(), refreshClaims)
		if err != nil {
			return nil, fmt.Errorf("ERR-check-refresh-04, could not parse claims %v", err)
		}
	} else {
		return nil, fmt.Errorf("ERR-check-refresh-05, could not parse claims, no algo found %v", tok.Headers[0].Algorithm)
	}
	t := time.Unix(refreshClaims.ExpiresAt, 0)
	if !t.After(timeNow()) {
		return nil, fmt.Errorf("ERR-check-refresh-06, expired %v", err)
	}
	return refreshClaims, nil
}

func encodeAccessToken(subject string, scope string, audience string,
	issuer string, inviteTokenSystem map[string]interface{},
	inviteTokenUser map[string]interface{}) (string, error) {
	tokenClaims := &TokenClaims{
		Scope:            scope,
		InviteMetaSystem: inviteTokenSystem,
		InviteMetaUser:   inviteTokenUser,
		Claims: jwt.Claims{
			Expiry:   jwt.NewNumericDate(timeNow().Add(tokenExp)),
			Subject:  subject,
			Audience: []string{audience},
			Issuer:   issuer,
			IssuedAt: jwt.NewNumericDate(timeNow()),
		},
	}

	var sig jose.Signer
	var err error
	if jwtKey != nil {
		sig, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: jwtKey}, (&jose.SignerOptions{}).WithType("JWT"))
	} else if privRSA != nil {
		sig, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privRSA}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", privRSAKid))
	} else if privEdDSA != nil {
		sig, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: *privEdDSA}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", privEdDSAKid))
	} else {
		return "", fmt.Errorf("JWT access token %v no key", tokenClaims.Subject)
	}

	if err != nil {
		return "", fmt.Errorf("JWT access token %v failed: %v", tokenClaims.Subject, err)
	}
	accessTokenString, err := jwt.Signed(sig).Claims(tokenClaims).CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("JWT access token %v failed: %v", tokenClaims.Subject, err)
	}
	if opts.Dev != "" {
		log.Printf("Access token: [%s]", accessTokenString)
	}
	return accessTokenString, nil
}

func encodeCodeToken(subject string, codeChallenge string, codeChallengeMethod string) (string, int64, error) {
	cc := &CodeClaims{}
	cc.Subject = subject
	cc.ExpiresAt = timeNow().Add(codeExp).Unix()
	cc.CodeChallenge = codeChallenge
	cc.CodeCodeChallengeMethod = codeChallengeMethod

	var sig jose.Signer
	var err error
	if jwtKey != nil {
		sig, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: jwtKey}, (&jose.SignerOptions{}).WithType("JWT"))
	} else if privRSA != nil {
		sig, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privRSA}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", privRSAKid))
	} else if privEdDSA != nil {
		sig, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: *privEdDSA}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", privEdDSAKid))
	} else {
		return "", 0, fmt.Errorf("JWT refresh token %v no key", subject)
	}

	if err != nil {
		return "", 0, fmt.Errorf("JWT refresh token %v failed: %v", subject, err)
	}
	codeToken, err := jwt.Signed(sig).Claims(cc).CompactSerialize()
	if err != nil {
		return "", 0, fmt.Errorf("JWT refresh token %v failed: %v", subject, err)
	}
	if opts.Dev != "" {
		log.Printf("Code token: [%s]", codeToken)
	}
	return codeToken, cc.ExpiresAt, nil
}

/*
 If the option ResetRefresh is set, then every time this function is called, which is
 before the createRefreshToken, then the refresh token is renewed and the old one is
 not valid anymore.

 This function is also used in case of revoking a token, where a new token is created,
 but not returned to the user, so the user has to login to get the refresh token
*/
func resetRefreshToken(oldToken string, email string) (string, error) {
	newToken, err := genToken()
	if err != nil {
		return "", err
	}
	err = updateRefreshToken(email, oldToken, newToken)
	if err != nil {
		return "", err
	}
	return newToken, nil
}

func checkRefresh(email string, token string) (string, string, int64, error) {
	result, err := findAuthByEmail(email)
	if err != nil {
		return "", "", 0, fmt.Errorf("ERR-refresh-03, DB select, %v err %v", email, err)
	}

	if result.emailToken != nil {
		return "", "", 0, fmt.Errorf("ERR-refresh-04, user %v no email verified: %v", email, err)
	}

	if result.refreshToken == "" || token != result.refreshToken {
		if opts.Dev != "" {
			log.Printf("refresh token mismatch %v != %v", token, result.refreshToken)
		}
		return "", "", 0, fmt.Errorf("ERR-refresh-05, refresh token mismatch")

	}
	return encodeTokens(result, email)
}

func encodeTokens(result *dbRes, email string) (string, string, int64, error) {
	jsonMapSystem, err := toJsonMap(result.metaSystem)
	if err != nil {
		return "", "", 0, fmt.Errorf("cannot encode system meta in encodeTokens for %v, %v", email, err)
	}
	jsonMapUser, err := toJsonMap(result.metaUser)
	if err != nil {
		return "", "", 0, fmt.Errorf("cannot encode user meta in encodeTokens for %v, %v", email, err)
	}

	encodedAccessToken, err := encodeAccessToken(email, opts.Scope, opts.Audience, opts.Issuer, jsonMapSystem, jsonMapUser)
	if err != nil {
		return "", "", 0, fmt.Errorf("ERR-refresh-06, cannot set access token for %v, %v", email, err)
	}

	refreshToken := result.refreshToken
	if opts.ResetRefresh {
		refreshToken, err = resetRefreshToken(refreshToken, email)
		if err != nil {
			return "", "", 0, fmt.Errorf("ERR-refresh-07, cannot reset access token for %v, %v", email, err)
		}
	}

	encodedRefreshToken, expiresAt, err := encodeRefreshToken(email, refreshToken)
	if err != nil {
		return "", "", 0, fmt.Errorf("ERR-refresh-08, cannot set refresh token for %v, %v", email, err)
	}
	return encodedAccessToken, encodedRefreshToken, expiresAt, nil
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
	if !t.After(timeNow()) {
		return nil, fmt.Errorf("ERR-check-refresh-06, expired %v", err)
	}
	return codeClaims, nil
}

func encodeRefreshToken(subject string, token string) (string, int64, error) {
	rc := &RefreshClaims{}
	rc.Subject = subject
	rc.ExpiresAt = timeNow().Add(refreshExp).Unix()
	rc.Token = token

	var sig jose.Signer
	var err error
	if jwtKey != nil {
		sig, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: jwtKey}, (&jose.SignerOptions{}).WithType("JWT"))
	} else if privRSA != nil {
		sig, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privRSA}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", privRSAKid))
	} else if privEdDSA != nil {
		sig, err = jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: *privEdDSA}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", privEdDSAKid))
	} else {
		return "", 0, fmt.Errorf("JWT refresh token %v no key", subject)
	}

	if err != nil {
		return "", 0, fmt.Errorf("JWT refresh token %v failed: %v", subject, err)
	}
	refreshToken, err := jwt.Signed(sig).Claims(rc).CompactSerialize()
	if err != nil {
		return "", 0, fmt.Errorf("JWT refresh token %v failed: %v", subject, err)
	}
	if opts.Dev != "" {
		log.Printf("Refresh token: [%s]", refreshToken)
	}
	return refreshToken, rc.ExpiresAt, nil
}

func toJsonMap(jsonStr *string) (map[string]interface{}, error) {
	jsonMap := make(map[string]interface{})
	if jsonStr != nil {
		err := json.Unmarshal([]byte(*jsonStr), &jsonMap)
		if err != nil {
			return nil, fmt.Errorf("ERR-refresh-06, cannot create json map %v", err)
		}
	}
	return jsonMap, nil
}
