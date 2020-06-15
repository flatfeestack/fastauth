package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

/*
curl -v "http://localhost:8080/signin"   -X POST   -d "{\"email\":\"tom\",\"password\":\"test\"}"   -H "Content-Type: application/json"
*/
func TestLogin(t *testing.T) {
	s, _ := server(&Opts{Port: 8081, DBPath: "/tmp", Url: "http://localhost:8081/send/{email}/{token}/{lang}"})

	type Payload struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	data := Payload{
		"tom",
		"test",
	}
	payloadBytes, err := json.Marshal(data)
	if err != nil {
		// handle err
	}
	body := bytes.NewReader(payloadBytes)

	req, err := http.NewRequest("POST", "http://localhost:8081/signin", body)
	if err != nil {
		// handle err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// handle err
	}
	defer resp.Body.Close()
	s.Shutdown(context.Background())
}
