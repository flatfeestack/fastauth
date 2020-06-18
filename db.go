package main

import (
	"database/sql"
	"fmt"
	"golang.org/x/crypto/scrypt"
	"time"
)

type dbRes struct {
	id        []byte
	password  []byte
	role      []byte
	salt      []byte
	activated time.Time
}

func dbSelect(email string) (*dbRes, error) {
	var res dbRes
	err := db.QueryRow("SELECT id, password, role, salt, activated from users where email = ?", email).Scan(&res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func getRefreshToken(email string) (string, error) {
	var refreshToken string
	err := db.QueryRow("SELECT refreshToken from users where email = ?", email).Scan(&refreshToken)
	if err != nil {
		return "", err
	}
	return refreshToken, nil
}

func insertUser(salt []byte, email string, password string, emailToken string) error {
	stmt, err := db.Prepare("INSERT INTO users (email, password, role, salt, emailToken) values (?, ?, 'USR', ?, ?)")
	if err != nil {
		return fmt.Errorf("prepare INSERT INTO users for %v statement failed: %v", email, err)
	}
	defer stmt.Close()

	dk, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, 32)
	res, err := stmt.Exec(email, dk, salt, emailToken)
	return handleErr(res, err, "INSERT INTO users", email)
}

func updateToken(email string, token string) error {
	stmt, err := db.Prepare("UPDATE users SET activated = CURRENT_TIMESTAMP, emailToken = NULL where email = ? and emailToken = ?")
	if err != nil {
		return fmt.Errorf("prepare UPDATE users for %v statement failed: %v", email, err)
	}
	defer stmt.Close()

	res, err := stmt.Exec(email, token)
	return handleErr(res, err, "UPDATE users", email)
}

func dbUpdateMailStatus(email string) error {
	stmt, err := db.Prepare("UPDATE users set emailSent = CURRENT_TIMESTAMP where email = ?")
	if err != nil {
		return fmt.Errorf("prepare UPDATE users status for %v statement failed: %v", email, err)
	}
	defer stmt.Close()

	res, err := stmt.Exec(email)
	return handleErr(res, err, "UPDATE users status", email)

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
