package cpoauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestExchangeAndFetchUser(t *testing.T) {
	t.Parallel()
	var baseURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			var request TokenRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.CodeVerifier != "verifier" || request.ClientSecret != "client-secret" {
				t.Fatalf("unexpected token request: %+v", request)
			}
			_ = json.NewEncoder(w).Encode(tokenResponse{AccessToken: "access-token", TokenType: "Bearer", ExpiresIn: 3600})
		case "/userinfo":
			if r.Header.Get("Authorization") != "Bearer access-token" {
				t.Fatalf("missing bearer token")
			}
			_ = json.NewEncoder(w).Encode(UserInfo{Sub: "cp-1", Username: "pilot", DisplayName: "飞行员", AvatarURL: "https://example.com/avatar.png"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	baseURL = server.URL
	client := New(baseURL+"/token", baseURL+"/userinfo", time.Second)
	user, err := client.ExchangeAndFetchUser(context.Background(), TokenRequest{Code: "code", CodeVerifier: "verifier", ClientSecret: "client-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if user.Sub != "cp-1" || user.Username != "pilot" {
		t.Fatalf("unexpected user: %+v", user)
	}
}
