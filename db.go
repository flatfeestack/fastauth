package main

import (
	"database/sql"
	"encoding/base32"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strings"
	"time"
)

type dbRes struct {
	password     []byte
	refreshToken string
	emailToken   *string
	sms          *string
	smsVerified  *time.Time
	totp         *string
	totpVerified *time.Time
	errorCount   int
	metaSystem   *string
	metaUser     *string
}

func findAuthByEmail(email string) (*dbRes, error) {
	var res dbRes
	var pw string
	query := `SELECT sms, password, meta_system, meta_user, refresh_token, 
       				 email_token, totp, sms_verified, totp_verified, error_count 
              FROM auth WHERE email = $1`
	err := db.QueryRow(query, email).Scan(
		&res.sms, &pw, &res.metaSystem, &res.metaUser, &res.refreshToken, &res.emailToken,
		&res.totp, &res.smsVerified, &res.totpVerified, &res.errorCount)

	if err != nil {
		return nil, err
	}
	res.password, err = base32.StdEncoding.DecodeString(pw)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func insertUser(email string, pwRaw []byte, emailToken string, refreshToken string, now time.Time) error {
	var pw *string
	if pwRaw != nil {
		s1 := base32.StdEncoding.EncodeToString(pwRaw)
		pw = &s1
	}
	stmt, err := db.Prepare(`INSERT INTO auth (email, password, email_token, refresh_token, created_at) 
								   VALUES ($1, $2, $3, $4, $5)`)
	if err != nil {
		return fmt.Errorf("prepare INSERT INTO auth for %v statement failed: %v", email, err)
	}
	defer closeAndLog(stmt)

	res, err := stmt.Exec(email, pw, emailToken, refreshToken, now)
	return handleErr(res, err, "INSERT INTO auth", email)
}

func deleteDbUser(email string) error {
	stmt, err := db.Prepare(`DELETE FROM auth where email = $1`)
	if err != nil {
		return fmt.Errorf("prepare INSERT INTO auth for %v statement failed: %v", email, err)
	}
	defer closeAndLog(stmt)

	res, err := stmt.Exec(email, email)
	return handleErr(res, err, "DELETE FROM auth", email)
}

func updateRefreshToken(email string, oldRefreshToken string, newRefreshToken string) error {
	stmt, err := db.Prepare("UPDATE auth SET refresh_token = $1 WHERE refresh_token = $2 and email=$3")
	if err != nil {
		return fmt.Errorf("prepare UPDATE refreshTokenfor statement failed: %v", err)
	}
	defer closeAndLog(stmt)

	res, err := stmt.Exec(newRefreshToken, oldRefreshToken, email)
	return handleErr(res, err, "UPDATE refreshToken", "n/a")
}

func updateSystemMeta(email string, systemMeta string) error {
	stmt, err := db.Prepare("UPDATE auth SET meta_system = $1 WHERE email=$2")
	if err != nil {
		return fmt.Errorf("prepare UPDATE meta_system statement failed: %v", err)
	}
	defer closeAndLog(stmt)

	res, err := stmt.Exec(systemMeta, email)
	return handleErr(res, err, "UPDATE meta_system", "n/a")
}

func updatePasswordInvite(email string, emailToken string, newPw []byte) error {
	pw := base32.StdEncoding.EncodeToString(newPw)
	stmt, err := db.Prepare(`UPDATE auth SET password = $1, email_token = NULL 
								   WHERE email = $2 AND email_token = $3 AND password IS NULL`)
	if err != nil {
		return fmt.Errorf("prepare UPDATE auth password for %v statement failed: %v", email, err)
	}
	defer closeAndLog(stmt)

	res, err := stmt.Exec(pw, email, emailToken)
	return handleErr(res, err, "UPDATE auth password invite", email)
}

func updatePasswordForgot(email string, forgetEmailToken string, newPw []byte) error {
	pw := base32.StdEncoding.EncodeToString(newPw)
	stmt, err := db.Prepare(`UPDATE auth SET password = $1, totp = NULL, sms = NULL, forget_email_token = NULL 
								   WHERE email = $2 AND forget_email_token = $3`)
	if err != nil {
		return fmt.Errorf("prepare UPDATE auth password for %v statement failed: %v", email, err)
	}
	defer closeAndLog(stmt)

	res, err := stmt.Exec(pw, email, forgetEmailToken)
	return handleErr(res, err, "UPDATE auth password", email)
}

func updateEmailForgotToken(email string, token string) error {
	//TODO: don't accept too old forget tokens
	stmt, err := db.Prepare("UPDATE auth SET forget_email_token = $1 WHERE email = $2")
	if err != nil {
		return fmt.Errorf("prepare UPDATE auth forgetEmailToken for %v statement failed: %v", email, err)
	}
	defer closeAndLog(stmt)

	res, err := stmt.Exec(token, email)
	return handleErr(res, err, "UPDATE auth forgetEmailToken", email)
}

func updateTOTP(email string, totp string) error {
	stmt, err := db.Prepare("UPDATE auth SET totp = $1 WHERE email = $2 and totp IS NULL")
	if err != nil {
		return fmt.Errorf("prepare UPDATE auth totp for %v statement failed: %v", email, err)
	}
	defer closeAndLog(stmt)

	res, err := stmt.Exec(totp, email)
	return handleErr(res, err, "UPDATE auth totp", email)
}

func updateSMS(email string, totp string, sms string) error {
	stmt, err := db.Prepare("UPDATE auth SET totp = $1, sms = $2 WHERE email = $3 AND sms_verified IS NULL")
	if err != nil {
		return fmt.Errorf("prepare UPDATE auth totp for %v statement failed: %v", email, err)
	}
	defer closeAndLog(stmt)

	res, err := stmt.Exec(totp, sms, email)
	return handleErr(res, err, "UPDATE auth totp", email)
}

func updateEmailToken(email string, token string) error {
	stmt, err := db.Prepare("UPDATE auth SET email_token = NULL WHERE email = $1 AND email_token = $2")
	if err != nil {
		return fmt.Errorf("prepare UPDATE auth for %v statement failed: %v", email, err)
	}
	defer closeAndLog(stmt)

	res, err := stmt.Exec(email, token)
	return handleErr(res, err, "UPDATE auth", email)
}

func updateSMSVerified(email string, now time.Time) error {
	stmt, err := db.Prepare("UPDATE auth SET sms_verified = $1 WHERE email = $2 AND sms IS NOT NULL")
	if err != nil {
		return fmt.Errorf("prepare UPDATE auth for %v statement failed: %v", email, err)
	}
	defer closeAndLog(stmt)

	res, err := stmt.Exec(now, email)
	return handleErr(res, err, "UPDATE auth SMS timestamp", email)
}

func updateTOTPVerified(email string, now time.Time) error {
	stmt, err := db.Prepare("UPDATE auth SET totp_verified = $1 WHERE email = $2 AND totp IS NOT NULL")
	if err != nil {
		return fmt.Errorf("prepare UPDATE auth for %v statement failed: %v", email, err)
	}
	defer closeAndLog(stmt)

	res, err := stmt.Exec(now, email)
	return handleErr(res, err, "UPDATE auth totp timestamp", email)
}

func incErrorCount(email string) error {
	stmt, err := db.Prepare("UPDATE auth set error_count = error_count + 1 WHERE email = $1")
	if err != nil {
		return fmt.Errorf("prepare UPDATE auth status for %v statement failed: %v", email, err)
	}
	defer closeAndLog(stmt)

	res, err := stmt.Exec(email)
	return handleErr(res, err, "UPDATE auth errorCount", email)
}

func resetCount(email string) error {
	stmt, err := db.Prepare("UPDATE auth set error_count = 0 WHERE email = $1")
	if err != nil {
		return fmt.Errorf("prepare UPDATE auth status for %v statement failed: %v", email, err)
	}
	defer closeAndLog(stmt)

	res, err := stmt.Exec(email)
	return handleErr(res, err, "UPDATE auth status", email)
}

func handleErr(res sql.Result, err error, info string, email string) error {
	if err != nil {
		return fmt.Errorf("%v query %v failed: %v", info, email, err)
	}
	nr, err := res.RowsAffected()
	if nr == 0 || err != nil {
		return fmt.Errorf("%v %v rows %v, affected or err: %v", info, nr, email, err)
	}
	return nil
}

///////// Setup
// Meta data can be additional information that will be encoded in the JWT token
func addInitialUserWithMeta(username string, password string, metaSystem *string, metaUser *string) error {
	res, err := findAuthByEmail(username)
	if res == nil || err != nil {
		dk, err := newPw(password, 0)
		if err != nil {
			return err
		}
		err = insertUser(username, dk, "emailToken", "refreshToken", timeNow())
		if err != nil {
			return err
		}
		err = updateEmailToken(username, "emailToken")
		if err != nil {
			return err
		}
		//update meta....
	}
	return nil
}

func initDB() (*sql.DB, error) {
	db, err := sql.Open(opts.DBDriver, opts.DBPath)
	if err != nil {
		return nil, err
	}

	//this will create or alter tables
	//https://stackoverflow.com/questions/12518876/how-to-check-if-a-file-exists-in-go
	for _, file := range strings.Split(opts.DBScripts, ":") {
		if file == "" {
			continue
		}
		//https://stackoverflow.com/questions/12518876/how-to-check-if-a-file-exists-in-go
		if _, err := os.Stat(file); err == nil {
			fileBytes, err := ioutil.ReadFile(file)
			if err != nil {
				return nil, err
			}

			//https://stackoverflow.com/questions/12682405/strip-out-c-style-comments-from-a-byte
			re := regexp.MustCompile("(?s)//.*?\n|/\\*.*?\\*/|(?s)--.*?\n|(?s)#.*?\n")
			newBytes := re.ReplaceAll(fileBytes, nil)

			requests := strings.Split(string(newBytes), ";")
			for _, request := range requests {
				request = strings.TrimSpace(request)
				if len(request) > 0 {
					_, err := db.Exec(request)
					if err != nil {
						return nil, fmt.Errorf("[%v] %v", request, err)
					}
				}
			}
		} else {
			log.Printf("ignoring file [%v] (%v)", file, err)
		}
	}

	return db, nil
}

func setupDB() {
	if opts.Users != "" {
		//add user for development
		users := strings.Split(opts.Users, ";")
		for _, user := range users {
			userPwMeta := strings.Split(user, ":")

			var metaSystem *string
			var metaUser *string
			if len(userPwMeta) >= 3 {
				metaSystem = &userPwMeta[2]
			}
			if len(userPwMeta) >= 4 {
				metaUser = &userPwMeta[3]
			}

			if len(userPwMeta) == 2 {
				err := addInitialUserWithMeta(userPwMeta[0], userPwMeta[1], metaSystem, metaUser)
				if err == nil {
					log.Printf("insterted user %v", userPwMeta[0])
				} else {
					log.Printf("could not insert %v: %v", userPwMeta[0], err)
				}
			} else {
				log.Printf("username and password need to be seperated by ':'")
			}
		}
	}
}

func closeAndLog(c io.Closer) {
	err := c.Close()
	if err != nil {
		log.Printf("could not close: %v", err)
	}
}
