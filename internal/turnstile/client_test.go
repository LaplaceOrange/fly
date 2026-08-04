package turnstile

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestVerifyValidatesHostnameAndAction(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("secret") != "secret" || r.Form.Get("response") != "token" || r.Form.Get("remoteip") != "203.0.113.9" {
			t.Fatalf("unexpected form: %v", r.Form)
		}
		_ = json.NewEncoder(w).Encode(Response{Success: true, Hostname: "fly.example.com", Action: "turnstile-spin-v2"})
	}))
	defer server.Close()
	client := NewWithEndpoint("secret", "fly.example.com", "turnstile-spin-v2", server.URL, time.Second)
	if err := client.Verify(context.Background(), "token", "203.0.113.9", "request-id"); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejectsInvalidAction(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(Response{Success: true, Hostname: "fly.example.com", Action: "other"})
	}))
	defer server.Close()
	client := NewWithEndpoint("secret", "fly.example.com", "turnstile-spin-v2", server.URL, time.Second)
	if err := client.Verify(context.Background(), "token", "", "request-id"); !IsInvalid(err) {
		t.Fatalf("expected invalid verification, got %v", err)
	}
}
