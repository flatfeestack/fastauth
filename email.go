package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func sendEmail(url string, e EmailRequest) error {
	c := &http.Client{
		Timeout: 15 * time.Second,
	}

	var jsonData []byte
	var err error
	if strings.Contains(url, "sendgrid") {
		sendGridReq := NewSingleEmailPlainText(
			NewEmail(opts.EmailFromName, opts.EmailFrom),
			e.Subject,
			NewEmail("", e.MailTo),
			e.TextMessage)
		jsonData, err = json.Marshal(sendGridReq)
	} else {
		jsonData, err = json.Marshal(e)
	}

	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Add("Authorization", "Bearer "+opts.EmailToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("could not send email: %v %v", resp.Status, resp.StatusCode)
	}
	return nil
}

func prepareEmail(mailTo string, data map[string]string, templateSubject string, defaultSubject string,
	templateText string, defaultText string, templateHtml string, lang string) EmailRequest {
	subject := parseTemplate(templateSubject+lang+".tmpl", data)
	if subject == "" {
		subject = defaultSubject
	}
	textMessage := parseTemplate(templateText+lang+".tmpl", data)
	if textMessage == "" {
		textMessage = defaultText
	}
	htmlMessage := parseTemplate(templateHtml+lang+".tmpl", data)

	return EmailRequest{
		MailTo:      mailTo,
		Subject:     subject,
		TextMessage: textMessage,
		HtmlMessage: htmlMessage,
	}
}
