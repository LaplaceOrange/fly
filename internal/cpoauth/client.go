package cpoauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client struct {
	tokenURL    string
	userInfoURL string
	http        *http.Client
}

type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	CodeVerifier string `json:"code_verifier"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type UserInfo struct {
	Sub         string `json:"sub"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	AvatarURL   string `json:"avatar_url"`
}

func New(tokenURL, userInfoURL string, timeout time.Duration) *Client {
	return &Client{tokenURL: tokenURL, userInfoURL: userInfoURL, http: &http.Client{Timeout: timeout}}
}

func (c *Client) ExchangeAndFetchUser(ctx context.Context, request TokenRequest) (UserInfo, error) {
	payload, err := json.Marshal(request)
	if err != nil {
		return UserInfo{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, bytes.NewReader(payload))
	if err != nil {
		return UserInfo{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	response, err := c.http.Do(req)
	if err != nil {
		return UserInfo{}, fmt.Errorf("cpoauth token request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return UserInfo{}, remoteError("cpoauth token exchange", response)
	}
	var token tokenResponse
	if err := decodeLimited(response.Body, &token); err != nil {
		return UserInfo{}, fmt.Errorf("decode cpoauth token response: %w", err)
	}
	if token.AccessToken == "" {
		return UserInfo{}, errors.New("cpoauth returned an empty access token")
	}

	userRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, c.userInfoURL, nil)
	if err != nil {
		return UserInfo{}, err
	}
	userRequest.Header.Set("Authorization", "Bearer "+token.AccessToken)
	userRequest.Header.Set("Accept", "application/json")
	userResponse, err := c.http.Do(userRequest)
	if err != nil {
		return UserInfo{}, fmt.Errorf("cpoauth userinfo request: %w", err)
	}
	defer userResponse.Body.Close()
	if userResponse.StatusCode < 200 || userResponse.StatusCode >= 300 {
		return UserInfo{}, remoteError("cpoauth userinfo", userResponse)
	}
	var user UserInfo
	if err := decodeLimited(userResponse.Body, &user); err != nil {
		return UserInfo{}, fmt.Errorf("decode cpoauth userinfo: %w", err)
	}
	if user.Sub == "" || user.Username == "" {
		return UserInfo{}, errors.New("cpoauth userinfo is missing sub or username")
	}
	if user.DisplayName == "" {
		user.DisplayName = user.Username
	}
	return user, nil
}

func decodeLimited(reader io.Reader, target any) error {
	decoder := json.NewDecoder(io.LimitReader(reader, 1<<20))
	return decoder.Decode(target)
}

func remoteError(prefix string, response *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
	return fmt.Errorf("%s returned %d: %s", prefix, response.StatusCode, string(body))
}
