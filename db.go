package main

import (
	"fmt"
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

func getToken(email string) (string, error) {
	var token string
	err := db.QueryRow("SELECT token from users where email = ?", email).Scan(&token)
	if err != nil {
		return "", err
	}
	return token, nil
}

func updateToken(email string, token string) error {
	stmt, err := db.Prepare("UPDATE users SET activated = CURRENT_TIMESTAMP, token = NULL where email = ? and token = ?")
	if err != nil {
		return fmt.Errorf("prepare %v statement failed: %v", email, err)
	}
	defer stmt.Close()

	res, err := stmt.Exec(email, token)
	if err != nil {
		return fmt.Errorf("prepare statement failed: %v", err)
	}
	nr, err := res.RowsAffected()
	if nr == 0 || err != nil {
		return fmt.Errorf("%v rows %v, affected or err: %v", nr, email, err)
	}
	return nil
}

func dbUpdateMailStatus(email string) error {
	stmt, err := db.Prepare("UPDATE users set emailSent = CURRENT_TIMESTAMP where email = ?")
	if err != nil {
		return fmt.Errorf("prepare update %v statement failed: %v", email, err)
	}
	defer stmt.Close()

	res, err := stmt.Exec(email)
	if err != nil {
		return fmt.Errorf("query %v failed: %v", email, err)
	}
	nr, err := res.RowsAffected()
	if nr == 0 || err != nil {
		return fmt.Errorf("%v rows %v, affected or err: %v", nr, email, err)
	}
	return nil
}
