package main

import (
	"database/sql"
	"fmt"
	"golang.org/x/crypto/scrypt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"
)

type dbRes struct {
	sms           *string
	password      []byte
	role          []byte
	salt          []byte
	emailVerified *time.Time
	smsVerified   *time.Time
	totpVerified  *time.Time
	refreshToken  *string
	totp          *string
	errorCount    *int
}

func dbSelect(email string) (*dbRes, error) {
	var res dbRes
	err := db.
		QueryRow("SELECT sms, password, role, salt, emailVerified, refreshToken, totp, smsVerified, totpVerified, errorCount FROM auth WHERE email = ?", email).
		Scan(&res.sms, &res.password, &res.role, &res.salt, &res.emailVerified, &res.refreshToken, &res.totp, &res.smsVerified, &res.totpVerified, &res.errorCount)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func insertUser(salt []byte, email string, dk []byte, emailToken string, refreshToken string) error {
	stmt, err := db.Prepare("INSERT INTO auth (email, password, role, salt, emailToken, refreshToken) VALUES (?, ?, 'USR', ?, ?, ?)")
	if err != nil {
		return fmt.Errorf("prepare INSERT INTO auth for %v statement failed: %v", email, err)
	}
	defer stmt.Close()

	res, err := stmt.Exec(email, dk, salt, emailToken, refreshToken)
	return handleErr(res, err, "INSERT INTO auth", email)
}

func updateRefreshToken(oldRefreshToken string, newRefreshToken string) error {
	stmt, err := db.Prepare("UPDATE auth SET refreshToken = ? WHERE refreshToken = ?")
	if err != nil {
		return fmt.Errorf("prepare UPDATE refreshTokenfor statement failed: %v", err)
	}
	defer stmt.Close()

	res, err := stmt.Exec(newRefreshToken, oldRefreshToken)
	return handleErr(res, err, "UPDATE refreshToken", "n/a")
}

func resetPassword(salt []byte, email string, dk []byte, forgetEmailToken string) error {
	stmt, err := db.Prepare("UPDATE auth SET password = ?, salt = ?, totp = NULL, sms = NULL WHERE email = ? AND forgetEmailToken = ?")
	if err != nil {
		return fmt.Errorf("prepare UPDATE auth password for %v statement failed: %v", email, err)
	}
	defer stmt.Close()

	res, err := stmt.Exec(dk, salt, email, forgetEmailToken)
	return handleErr(res, err, "UPDATE auth password", email)
}

func updateEmailForgotToken(email string, token string) error {
	//TODO: don't accept too old forget tokens
	stmt, err := db.Prepare("UPDATE auth SET forgetEmail = CURRENT_TIMESTAMP, forgetEmailToken = ? WHERE email = ?")
	if err != nil {
		return fmt.Errorf("prepare UPDATE auth forgetEmailToken for %v statement failed: %v", email, err)
	}
	defer stmt.Close()

	res, err := stmt.Exec(token, email)
	return handleErr(res, err, "UPDATE auth forgetEmailToken", email)
}

func updateTOTP(email string, totp string) error {
	stmt, err := db.Prepare("UPDATE auth SET totp = ? WHERE email = ? and totp IS NULL")
	if err != nil {
		return fmt.Errorf("prepare UPDATE auth totp for %v statement failed: %v", email, err)
	}
	defer stmt.Close()

	res, err := stmt.Exec(totp, email)
	return handleErr(res, err, "UPDATE auth totp", email)
}

func updateSMS(email string, totp string, sms string) error {
	stmt, err := db.Prepare("UPDATE auth SET totp = ?, sms = ? WHERE email = ? AND smsVerified IS NULL")
	if err != nil {
		return fmt.Errorf("prepare UPDATE auth totp for %v statement failed: %v", email, err)
	}
	defer stmt.Close()

	res, err := stmt.Exec(totp, sms, email)
	return handleErr(res, err, "UPDATE auth totp", email)
}

func updateEmailToken(email string, token string) error {
	stmt, err := db.Prepare("UPDATE auth SET emailVerified = CURRENT_TIMESTAMP, emailToken = NULL WHERE email = ? AND emailToken = ?")
	if err != nil {
		return fmt.Errorf("prepare UPDATE auth for %v statement failed: %v", email, err)
	}
	defer stmt.Close()

	res, err := stmt.Exec(email, token)
	return handleErr(res, err, "UPDATE auth", email)
}

func updateSMSVerified(email string) error {
	stmt, err := db.Prepare("UPDATE auth SET smsVerified = CURRENT_TIMESTAMP WHERE email = ? AND sms IS NOT NULL")
	if err != nil {
		return fmt.Errorf("prepare UPDATE auth for %v statement failed: %v", email, err)
	}
	defer stmt.Close()

	res, err := stmt.Exec(email)
	return handleErr(res, err, "UPDATE auth SMS timestamp", email)
}

func updateTOTPVerified(email string) error {
	stmt, err := db.Prepare("UPDATE auth SET totpVerified = CURRENT_TIMESTAMP WHERE email = ? AND totp IS NOT NULL")
	if err != nil {
		return fmt.Errorf("prepare UPDATE auth for %v statement failed: %v", email, err)
	}
	defer stmt.Close()

	res, err := stmt.Exec(email)
	return handleErr(res, err, "UPDATE auth totp timestamp", email)
}

func updateMailStatus(email string) error {
	stmt, err := db.Prepare("UPDATE auth set emailSent = CURRENT_TIMESTAMP WHERE email = ?")
	if err != nil {
		return fmt.Errorf("prepare auth auth status for %v statement failed: %v", email, err)
	}
	defer stmt.Close()

	res, err := stmt.Exec(email)
	return handleErr(res, err, "UPDATE auth status", email)
}

func incErrorCount(email string) error {
	stmt, err := db.Prepare("UPDATE auth set errorCount = errorCount + 1 WHERE email = ?")
	if err != nil {
		return fmt.Errorf("prepare UPDATE auth status for %v statement failed: %v", email, err)
	}
	defer stmt.Close()

	res, err := stmt.Exec(email)
	return handleErr(res, err, "UPDATE auth status", email)
}

func resetCount(email string) error {
	stmt, err := db.Prepare("UPDATE auth set errorCount = 0 WHERE email = ?")
	if err != nil {
		return fmt.Errorf("prepare UPDATE auth status for %v statement failed: %v", email, err)
	}
	defer stmt.Close()

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

func addInitialUser(username string, password string) error {
	res, err := dbSelect(username)
	if res == nil || err != nil {
		salt := []byte{0}
		dk, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, 32)
		if err != nil {
			return err
		}
		err = insertUser(salt, username, dk, "emailToken", "refreshToken")
		if err != nil {
			return err
		}
		err = updateEmailToken(username, "emailToken")
		if err != nil {
			return err
		}
	}
	return nil
}

func initDB() (*sql.DB, error) {
	db, err := sql.Open(options.DBDriver, options.DBPath)
	if err != nil {
		return nil, err
	}

	//this will create or alter tables
	//https://stackoverflow.com/questions/12518876/how-to-check-if-a-file-exists-in-go
	if _, err := os.Stat("startup.sql"); err == nil {
		file, err := ioutil.ReadFile("startup.sql")
		if err != nil {
			return nil, err
		}
		requests := strings.Split(string(file), ";")
		for _, request := range requests {
			request = strings.Replace(request, "\n", "", -1)
			request = strings.Replace(request, "\t", "", -1)
			if !strings.HasPrefix(request, "#") {
				_, err = db.Exec(request)
				if err != nil {
					return nil, fmt.Errorf("[%v] %v", request, err)
				}
			}
		}
	}

	return db, nil
}

func setupDB() {
	if options.Users != "" {
		//add user for development
		users := strings.Split(options.Users, ";")
		for _, user := range users {
			userpw := strings.Split(user, ":")
			if len(userpw) == 2 {
				err := addInitialUser(userpw[0], userpw[1])
				if err == nil {
					log.Printf("insterted user %v", userpw[0])
				} else {
					log.Printf("could not insert %v", userpw[0])
				}
			} else {
				log.Printf("username and password need to be seperated by ':'")
			}
		}
	}
}
