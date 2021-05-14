package main

import (
	"database/sql"
	"encoding/base32"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"
)

type dbRes struct {
	password     []byte
	refreshToken string
	emailToken   *string
	inviteToken  string
	sms          *string
	smsVerified  *time.Time
	totp         *string
	totpVerified *time.Time
	errorCount   int
	meta         *string
	inviteEmails *string
	inviteMeta   *string
}

type dbInvite struct {
	Email       string     `json:"email"`
	Meta        string     `json:"meta"`
	ConfirmedAt *time.Time `json:"confirmedAt"`
	CreatedAt   time.Time  `json:"createdAt"`
}

func findAuthByEmail(email string) (*dbRes, error) {
	var res dbRes
	var pw string
	query := `SELECT a.sms, a.password, a.meta, a.refresh_token, a.email_token, 
                     a.invite_token, a.totp, a.sms_verified, a.totp_verified, 
                     a.error_count, 
                     (SELECT ` + agg("i.invite_email") + `
                      FROM invite i 
                      WHERE i.email=a.email AND i.confirmed_at IS NOT NULL) as invite_token,
                     (SELECT ` + agg("i.meta") + `
                      FROM invite i 
                      WHERE i.email=a.email AND i.confirmed_at IS NOT NULL) as invite_meta
			  FROM auth a
              WHERE a.email = $1`
	err := db.QueryRow(query, email).Scan(
		&res.sms, &pw, &res.meta, &res.refreshToken, &res.emailToken, &res.inviteToken,
		&res.totp, &res.smsVerified, &res.totpVerified, &res.errorCount, &res.inviteEmails, &res.inviteMeta)

	if err != nil {
		return nil, err
	}
	res.password, err = base32.StdEncoding.DecodeString(pw)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func findInvitationsByEmail(email string) ([]dbInvite, error) {
	var res []dbInvite
	query := `SELECT email, confirmed_at, meta, created_at 
              FROM invite 
              WHERE invite_email=$1`
	rows, err := db.Query(query, email)

	switch err {
	case sql.ErrNoRows:
		return nil, nil
	case nil:
		defer closeAndLog(rows)
		for rows.Next() {
			var inv dbInvite
			err = rows.Scan(&inv.Email, &inv.ConfirmedAt, &inv.Meta, &inv.CreatedAt)
			if err != nil {
				return nil, err
			}
			res = append(res, inv)
		}
		return res, nil
	default:
		return nil, err
	}
}

func deleteInvite(myEmail string, inviteEmail string) error {
	stmt, err := db.Prepare("DELETE FROM invite WHERE email = $1 AND invite_email = $2")
	if err != nil {
		return fmt.Errorf("prepare DELETE FROM invite %v statement failed: %v", myEmail, err)
	}
	defer closeAndLog(stmt)

	res, err := stmt.Exec(myEmail, inviteEmail)
	return handleErr(res, err, "DELETE invite", myEmail)
}

func updateInviteToken(email string, inviteToken string) error {
	stmt, err := db.Prepare(`UPDATE auth SET invite_token = $1 WHERE email = $2`)
	if err != nil {
		return fmt.Errorf("prepare UPDATE inviteToken for %v statement failed: %v", email, err)
	}
	defer closeAndLog(stmt)

	res, err := stmt.Exec(inviteToken, email)
	return handleErr(res, err, "UPDATE inviteToken", email)
}

func insertInvite(email string, inviteEmail string, meta string, now time.Time) error {
	stmt, err := db.Prepare("INSERT INTO invite (email, invite_email, meta, created_at) VALUES ($1, $2, $3, $4)")
	if err != nil {
		return fmt.Errorf("prepare INSERT INTO invite for %v statement failed: %v", email, err)
	}
	defer closeAndLog(stmt)

	res, err := stmt.Exec(email, inviteEmail, meta, now)
	return handleErr(res, err, "INSERT INTO auth", email)
}

func insertUser(email string, pwRaw []byte, meta *string, emailToken string, refreshToken string, inviteToken string, now time.Time) error {
	pw := base32.StdEncoding.EncodeToString(pwRaw)
	stmt, err := db.Prepare("INSERT INTO auth (email, password, meta, email_token, refresh_token, invite_token, created_at) " +
		"VALUES ($1, $2, $3, $4, $5, $6, $7)")
	if err != nil {
		return fmt.Errorf("prepare INSERT INTO auth for %v statement failed: %v", email, err)
	}
	defer closeAndLog(stmt)

	res, err := stmt.Exec(email, pw, meta, emailToken, refreshToken, inviteToken, now)
	return handleErr(res, err, "INSERT INTO auth", email)
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

func updatePasswordInvite(email string, emailToken string, newPw []byte) error {
	pw := base32.StdEncoding.EncodeToString(newPw)
	stmt, err := db.Prepare("UPDATE auth SET password = $1, email_token = NULL WHERE email = $2 AND email_token = $3")
	if err != nil {
		return fmt.Errorf("prepare UPDATE auth password for %v statement failed: %v", email, err)
	}
	defer closeAndLog(stmt)

	res, err := stmt.Exec(pw, email, emailToken)
	return handleErr(res, err, "UPDATE auth password invite", email)
}

func updateConfirmInviteAt(email string, inviteEmail string, now time.Time) error {
	stmt, err := db.Prepare("UPDATE invite SET confirmed_at = $1 WHERE email = $2 and invite_email=$3")
	if err != nil {
		return fmt.Errorf("prepare UPDATE invite statement failed: %v", err)
	}
	defer closeAndLog(stmt)

	res, err := stmt.Exec(now, email, inviteEmail)
	return handleErr(res, err, "UPDATE invite", email)
}

func updatePasswordForgot(email string, forgetEmailToken string, newPw []byte) error {
	pw := base32.StdEncoding.EncodeToString(newPw)
	stmt, err := db.Prepare("UPDATE auth SET password = $1, totp = NULL, sms = NULL, forget_email_token = NULL WHERE email = $2 AND forget_email_token = $3")
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

func addInitialUserWithMeta(username string, password string, meta *string) error {
	res, err := findAuthByEmail(username)
	if res == nil || err != nil {
		dk, err := newPw(password, 0)
		if err != nil {
			return err
		}
		err = insertUser(username, dk, meta, "emailToken", "refreshToken", "inviteToken", timeNow())
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
	db, err := sql.Open(opts.DBDriver, opts.DBPath)
	if err != nil {
		return nil, err
	}

	//this will create or alter tables
	//https://stackoverflow.com/questions/12518876/how-to-check-if-a-file-exists-in-go
	for _, v := range strings.Split(opts.DBScripts, ":") {
		if _, err := os.Stat(v); err == nil {
			file, err := ioutil.ReadFile(v)
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
	}

	return db, nil
}

func setupDB() {
	if opts.Users != "" {
		//add user for development
		users := strings.Split(opts.Users, ";")
		for _, user := range users {
			userPwMeta := strings.Split(user, ":")
			if len(userPwMeta) == 2 {
				err := addInitialUserWithMeta(userPwMeta[0], userPwMeta[1], nil)
				if err == nil {
					log.Printf("insterted user %v", userPwMeta[0])
				} else {
					log.Printf("could not insert %v: %v", userPwMeta[0], err)
				}
			} else if len(userPwMeta) == 3 {
				meta := userPwMeta[2]
				err := addInitialUserWithMeta(userPwMeta[0], userPwMeta[1], &meta)
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

func agg(column string) string {
	agg := "string_agg(" + column + ", ',')"
	if opts.DBDriver == "sqlite3" {
		agg = "group_concat(" + column + ", ',')"
	}
	return agg
}
