package message

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
)

var (
	NEXMO_API_KEY    = os.Getenv("my_api_key")
	NEXMO_API_SECRET = os.Getenv("my_secret")
)

type From struct {
	Type   string `json:"type"`
	Number string `json:"number"`
}
type To struct {
	Type   string `json:"type"`
	Number string `json:"number"`
}
type Content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}
type Message struct {
	Content Content `json:"content"`
}

type Payload struct {
	From    From    `json:"from"`
	To      To      `json:"to"`
	Message Message `json:"message"`
}

func SendMessage(username, phone string) (*http.Response, error) {
	data := Payload{
		From: From{
			Type:   "sms",
			Number: "Nexmo",
		},
		To: To{
			Type:   "sms",
			Number: phone,
		},
		Message: Message{
			Content: Content{
				Type: "text",
				Text: "Dear " + username + ", a todo was created from your account just now.",
			},
		},
	}
	payloadBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	body := bytes.NewReader(payloadBytes)

	req, err := http.NewRequest("POST", "https://api.nexmo.com/v0.1/messages", body)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(NEXMO_API_KEY, NEXMO_API_SECRET)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return resp, nil
}
