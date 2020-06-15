package main

import (
	"fmt"
	"log"
)

func dbSelect(email string) (*dbRes, error) {
	stmt, err := db.Prepare("SELECT id, password, role, salt, activated from users where email = ?")
	if err != nil {
		log.Printf("prepare %v statement failed: %v", email, err)
		return nil, err
	}
	res, err := stmt.Query(email)
	if err != nil {
		log.Printf("query %v failed: %v", email, err)
		return nil, err
	}
	if res.Err() != nil {
		log.Printf("response %v failed: %v", email, err)
		return nil, err
	}

	var result *dbRes
	err = res.Scan(&result)
	if err != nil {
		log.Printf("scan %v failed: %v", email, err)
		return nil, err
	}
	if res.Err() != nil {
		log.Printf("scan %v failed: %v", email, err)
		return nil, res.Err()
	}
	return result, nil
}

func dbUpdateMailStatus(email string) error {
	stmt, err := db.Prepare("UPDATE users set emailSent = CURRENT_TIMESTAMP where email = ?")
	if err != nil {
		log.Printf("prepare update %v statement failed: %v", email, err)
		return err
	}
	res, err := stmt.Exec(email)
	if err != nil {
		log.Printf("query %v failed: %v", email, err)
		return err
	}
	nr, err := res.RowsAffected()
	if err != nil {
		log.Printf("%v rows %v, affected or err: %v", nr, email, err)
		return err
	}
	if nr == 0 {
		return fmt.Errorf("%v rows for %v affected", nr, email)
	}
	return nil
}
