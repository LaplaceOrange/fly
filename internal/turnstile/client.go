package turnstile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const siteverifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

type Client struct {
	secret           string
	expectedHostname string
	expectedAction   string
	http             *http.Client
	endpoint         string
}

type Response struct {
	Success     bool     `json:"success"`
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	Action      string   `json:"action"`
	ErrorCodes  []string `json:"error-codes"`
}

type InvalidError struct {
	Codes []string
}

func (e *InvalidError) Error() string {
	return "turnstile verification failed: " + strings.Join(e.Codes, ",")
}

func New(secret, expectedHostname, expectedAction string, timeout time.Duration) *Client {
	return &Client{
		secret: secret, expectedHostname: expectedHostname, expectedAction: expectedAction,
		http: &http.Client{Timeout: timeout}, endpoint: siteverifyURL,
	}
}

func NewWithEndpoint(secret, expectedHostname, expectedAction, endpoint string, timeout time.Duration) *Client {
	client := New(secret, expectedHostname, expectedAction, timeout)
	client.endpoint = endpoint
	return client
}

func (c *Client) Verify(ctx context.Context, token, remoteIP, idempotencyKey string) error {
	if strings.TrimSpace(token) == "" {
		return &InvalidError{Codes: []string{"missing-input-response"}}
	}
	form := url.Values{
		"secret":          {c.secret},
		"response":        {token},
		"idempotency_key": {idempotencyKey},
	}
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	response, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("turnstile siteverify: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("turnstile siteverify returned %d", response.StatusCode)
	}
	var result Response
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&result); err != nil {
		return fmt.Errorf("decode turnstile response: %w", err)
	}
	if !result.Success {
		if len(result.ErrorCodes) == 0 {
			result.ErrorCodes = []string{"verification-failed"}
		}
		return &InvalidError{Codes: result.ErrorCodes}
	}
	if c.expectedHostname != "" && !strings.EqualFold(result.Hostname, c.expectedHostname) {
		return &InvalidError{Codes: []string{"hostname-mismatch"}}
	}
	if c.expectedAction != "" && result.Action != c.expectedAction {
		return &InvalidError{Codes: []string{"action-mismatch"}}
	}
	return nil
}

func IsInvalid(err error) bool {
	var invalid *InvalidError
	return errors.As(err, &invalid)
}
