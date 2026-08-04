package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"testing/fstest"
	"time"

	"github.com/LaplaceOrange/fly/internal/config"
	"github.com/LaplaceOrange/fly/internal/cpoauth"
	"github.com/LaplaceOrange/fly/internal/realtime"
	"github.com/LaplaceOrange/fly/internal/store"
	"github.com/coder/websocket"
)

type oauthMock struct{}

func (oauthMock) ExchangeAndFetchUser(_ context.Context, request cpoauth.TokenRequest) (cpoauth.UserInfo, error) {
	return cpoauth.UserInfo{Sub: "oauth-user", Username: "oauth-pilot", DisplayName: "OAuth Pilot"}, nil
}

type turnstileMock struct{ err error }

func (mock turnstileMock) Verify(context.Context, string, string, string) error { return mock.err }

func TestOAuthLoginCallbackCreatesSession(t *testing.T) {
	t.Parallel()
	testServer, _ := newTestServer(t)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	loginResponse, err := client.Get(testServer.URL + "/api/auth/login?return_to=/after")
	if err != nil {
		t.Fatal(err)
	}
	defer loginResponse.Body.Close()
	if loginResponse.StatusCode != http.StatusFound {
		t.Fatalf("login returned %d", loginResponse.StatusCode)
	}
	location, err := url.Parse(loginResponse.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Query().Get("code_challenge_method") != "S256" || location.Query().Get("state") == "" {
		t.Fatalf("invalid authorization URL: %s", location)
	}
	callbackURL := testServer.URL + "/api/auth/callback?code=test-code&state=" + url.QueryEscape(location.Query().Get("state"))
	callbackResponse, err := client.Get(callbackURL)
	if err != nil {
		t.Fatal(err)
	}
	defer callbackResponse.Body.Close()
	if callbackResponse.StatusCode != http.StatusFound || callbackResponse.Header.Get("Location") != "/after" {
		t.Fatalf("callback returned %d -> %q", callbackResponse.StatusCode, callbackResponse.Header.Get("Location"))
	}
	meResponse, err := client.Get(testServer.URL + "/api/me")
	if err != nil {
		t.Fatal(err)
	}
	defer meResponse.Body.Close()
	var me map[string]any
	if err := json.NewDecoder(meResponse.Body).Decode(&me); err != nil {
		t.Fatal(err)
	}
	if authenticated, _ := me["authenticated"].(bool); !authenticated {
		t.Fatalf("expected authenticated session: %#v", me)
	}
}

func TestFlightRateLimitAndRealtimeBroadcast(t *testing.T) {
	t.Parallel()
	testServer, database := newTestServer(t)
	ctx := context.Background()
	now := time.Now().UTC()
	user, err := database.UpsertUser(ctx, store.User{ID: "pilot-1", Username: "pilot", DisplayName: "Pilot"}, now)
	if err != nil {
		t.Fatal(err)
	}
	token := "session-token"
	if err := database.CreateSession(ctx, store.SessionHash(token), user.ID, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	wsURL := "ws" + testServer.URL[len("http"):] + "/api/realtime"
	connection, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.CloseNow()
	readCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, _, err := connection.Read(readCtx); err != nil {
		t.Fatalf("read connected event: %v", err)
	}

	post := func() *http.Response {
		request, err := http.NewRequest(http.MethodPost, testServer.URL+"/api/flights", bytes.NewBufferString(`{"turnstileToken":"valid-token"}`))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", "http://example.com")
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	first := post()
	io.Copy(io.Discard, first.Body)
	first.Body.Close()
	if first.StatusCode != http.StatusCreated {
		t.Fatalf("first takeoff returned %d", first.StatusCode)
	}
	_, payload, err := connection.Read(readCtx)
	if err != nil {
		t.Fatalf("read flight event: %v", err)
	}
	var event realtime.Event
	if err := json.Unmarshal(payload, &event); err != nil || event.Type != "flight.created" {
		t.Fatalf("unexpected event: %s (%v)", payload, err)
	}
	second := post()
	io.Copy(io.Discard, second.Body)
	second.Body.Close()
	if second.StatusCode != http.StatusTooManyRequests || second.Header.Get("Retry-After") == "" {
		t.Fatalf("second takeoff returned %d, retry-after=%q", second.StatusCode, second.Header.Get("Retry-After"))
	}
}

func TestSignedShareHTTPFlow(t *testing.T) {
	t.Parallel()
	testServer, database := newTestServer(t)
	ctx := context.Background()
	now := time.Now().UTC()
	user, err := database.UpsertUser(ctx, store.User{ID: "share-user", Username: "sharer", DisplayName: "Sharer"}, now)
	if err != nil {
		t.Fatal(err)
	}
	sessionToken := "share-session"
	if err := database.CreateSession(ctx, store.SessionHash(sessionToken), user.ID, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := publicJWK{
		Kty: "EC", Crv: "P-256", X: base64.RawURLEncoding.EncodeToString(pad32(privateKey.X)),
		Y: base64.RawURLEncoding.EncodeToString(pad32(privateKey.Y)), Ext: true, KeyOps: []string{"verify"},
	}
	keyResponse := authenticatedJSON(t, testServer.URL+"/api/keys", sessionToken, map[string]any{"publicJwk": jwk})
	defer keyResponse.Body.Close()
	if keyResponse.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(keyResponse.Body)
		t.Fatalf("key registration returned %d: %s", keyResponse.StatusCode, body)
	}
	var registered struct {
		KeyID string `json:"keyId"`
	}
	if err := json.NewDecoder(keyResponse.Body).Decode(&registered); err != nil {
		t.Fatal(err)
	}
	payload := `{"version":1,"message":"signed"}`
	digest := sha256.Sum256([]byte(shareSigningInput(false, payload, "")))
	rValue, sValue, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := base64.RawURLEncoding.EncodeToString(append(pad32(rValue), pad32(sValue)...))
	shareResponse := authenticatedJSON(t, testServer.URL+"/api/shares", sessionToken, map[string]any{
		"encrypted": false, "payload": payload, "iv": "", "signature": signature, "keyId": registered.KeyID,
	})
	defer shareResponse.Body.Close()
	if shareResponse.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(shareResponse.Body)
		t.Fatalf("share creation returned %d: %s", shareResponse.StatusCode, body)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(shareResponse.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	response, err := http.Get(testServer.URL + "/api/shares/" + created.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("share fetch returned %d", response.StatusCode)
	}
}

func authenticatedJSON(t *testing.T, endpoint, token string, payload any) *http.Response {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://example.com")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func newTestServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	database, err := store.Open(filepath.Join(t.TempDir(), "server.db"), time.FixedZone("CST", 8*60*60))
	if err != nil {
		t.Fatal(err)
	}
	baseURL, _ := url.Parse("http://example.com")
	cfg := config.Config{
		SiteName: "中国人能飞", PublicBaseURL: baseURL, ListenAddr: ":0", DatabasePath: "unused",
		Location: time.FixedZone("CST", 8*60*60), CPOAuthClientID: "client", CPOAuthClientSecret: "secret",
		CPOAuthAuthorizeURL: "https://www.cpoauth.com/api/oauth/authorize", CPOAuthTokenURL: "https://www.cpoauth.com/api/oauth/token",
		CPOAuthUserInfoURL: "https://www.cpoauth.com/api/oauth/userinfo", CPOAuthScopes: "openid profile",
		TurnstileSiteKey: "site-key", TurnstileSecretKey: "secret-key", TurnstileExpectedAction: "turnstile-spin-v2",
		TakeoffRateLimit: 10 * time.Minute, SessionSecret: []byte("01234567890123456789012345678901"),
		SessionTTL: 24 * time.Hour, ShareTTL: 7 * 24 * time.Hour,
	}
	frontend := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("<!doctype html><title>test</title>")}}
	hub := realtime.NewHub()
	app := New(Dependencies{
		Config: cfg, Store: database, CPOAuth: oauthMock{}, Turnstile: turnstileMock{}, Hub: hub,
		FrontendFS: frontend, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	testServer := httptest.NewServer(app.Handler())
	t.Cleanup(func() { hub.Close(); testServer.Close(); _ = database.Close() })
	return testServer, database
}
