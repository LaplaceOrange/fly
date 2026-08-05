package server

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
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

func TestRandomUUIDUsesRFC4122Version4Format(t *testing.T) {
	value, err := randomUUID()
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(value) {
		t.Fatalf("randomUUID returned %q, want RFC 4122 v4 UUID", value)
	}
}

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
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := okpPublicJWK{
		Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(publicKey), Alg: "EdDSA", Ext: true, KeyOps: []string{"verify"},
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
	payload := `{"version":1,"sharedAt":"2026-01-01T00:00:00Z","message":"signed","user":{"id":"share-user","username":"sharer","displayName":"Sharer","avatarUrl":"","totalFlights":0,"lastFlightAt":null},"snapshot":{"totalFlights":0,"totalUsers":1,"rangeFlights":0,"range":"24h"}}`
	expiresAt := now.Add(30 * time.Minute).Format(time.RFC3339Nano)
	shareToSign := shareRequest{Encrypted: false, Payload: payload, SenderUserID: user.ID, SignatureVersion: 3, CryptoSuite: publicCryptoSuite, ExpiresAt: expiresAt}
	signature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(modernShareSigningInput(shareToSign))))
	shareResponse := authenticatedJSON(t, testServer.URL+"/api/shares", sessionToken, map[string]any{
		"encrypted": false, "payload": payload, "iv": "", "signature": signature, "keyId": registered.KeyID,
		"senderUserId": user.ID, "signatureVersion": 3, "cryptoSuite": publicCryptoSuite, "recipientUserId": "", "keyEnvelopes": []any{}, "expiresAt": expiresAt,
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

func TestEncryptedShareRequiresIntendedRecipient(t *testing.T) {
	t.Parallel()
	testServer, database := newTestServer(t)
	ctx := context.Background()
	now := time.Now().UTC()
	sender, err := database.UpsertUser(ctx, store.User{ID: "sender", Username: "sender", DisplayName: "Sender"}, now)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := database.UpsertUser(ctx, store.User{ID: "recipient", Username: "recipient", DisplayName: "Recipient"}, now)
	if err != nil {
		t.Fatal(err)
	}
	for token, userID := range map[string]string{"sender-session": sender.ID, "recipient-session": recipient.ID} {
		if err := database.CreateSession(ctx, store.SessionHash(token), userID, now, now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	signingPublic, signingPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingResponse := authenticatedJSON(t, testServer.URL+"/api/keys", "sender-session", map[string]any{"publicJwk": okpPublicJWK{
		Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(signingPublic),
	}})
	defer signingResponse.Body.Close()
	var signingRegistered struct {
		KeyID string `json:"keyId"`
	}
	if err := json.NewDecoder(signingResponse.Body).Decode(&signingRegistered); err != nil {
		t.Fatal(err)
	}
	recipientSigningPublic, recipientSigningPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipientSigningResponse := authenticatedJSON(t, testServer.URL+"/api/keys", "recipient-session", map[string]any{"publicJwk": okpPublicJWK{
		Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(recipientSigningPublic),
	}})
	defer recipientSigningResponse.Body.Close()
	var recipientSigningRegistered struct {
		KeyID string `json:"keyId"`
	}
	if err := json.NewDecoder(recipientSigningResponse.Body).Decode(&recipientSigningRegistered); err != nil {
		t.Fatal(err)
	}
	recipientPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	exchangeJWK := okpPublicJWK{Kty: "OKP", Crv: "X25519", X: base64.RawURLEncoding.EncodeToString(recipientPrivate.PublicKey().Bytes())}
	invalidBindingResponse := authenticatedJSON(t, testServer.URL+"/api/exchange-keys", "recipient-session", map[string]any{
		"publicJwk": exchangeJWK, "signingKeyId": recipientSigningRegistered.KeyID, "bindingVersion": 1,
		"bindingSignature": base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
	})
	invalidBindingResponse.Body.Close()
	if invalidBindingResponse.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid exchange binding returned %d", invalidBindingResponse.StatusCode)
	}
	bindingSignature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(recipientSigningPrivate,
		[]byte(exchangeKeyBindingInput(recipient.ID, recipientSigningRegistered.KeyID, exchangeJWK))))
	exchangeResponse := authenticatedJSON(t, testServer.URL+"/api/exchange-keys", "recipient-session", map[string]any{
		"publicJwk": exchangeJWK, "signingKeyId": recipientSigningRegistered.KeyID,
		"bindingVersion": 1, "bindingSignature": bindingSignature,
	})
	defer exchangeResponse.Body.Close()
	if exchangeResponse.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(exchangeResponse.Body)
		t.Fatalf("exchange key registration returned %d: %s", exchangeResponse.StatusCode, body)
	}
	var exchangeRegistered struct {
		KeyID string `json:"keyId"`
	}
	if err := json.NewDecoder(exchangeResponse.Body).Decode(&exchangeRegistered); err != nil {
		t.Fatal(err)
	}
	prekeyPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	prekeyJWK := okpPublicJWK{Kty: "OKP", Crv: "X25519", X: base64.RawURLEncoding.EncodeToString(prekeyPrivate.PublicKey().Bytes())}
	prekeySignature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(recipientSigningPrivate,
		[]byte(prekeyBindingInput(recipient.ID, recipientSigningRegistered.KeyID, exchangeRegistered.KeyID, prekeyJWK))))
	prekeyResponse := authenticatedJSON(t, testServer.URL+"/api/prekeys", "recipient-session", map[string]any{"prekeys": []any{map[string]any{
		"publicJwk": prekeyJWK, "exchangeKeyId": exchangeRegistered.KeyID, "signingKeyId": recipientSigningRegistered.KeyID,
		"bindingVersion": 1, "bindingSignature": prekeySignature,
	}}})
	defer prekeyResponse.Body.Close()
	if prekeyResponse.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(prekeyResponse.Body)
		t.Fatalf("prekey registration returned %d: %s", prekeyResponse.StatusCode, body)
	}
	directoryResponse := authenticatedGet(t, testServer.URL+"/api/share-recipients/"+recipient.ID+"/keys", "sender-session")
	defer directoryResponse.Body.Close()
	var directory struct {
		Keys []struct {
			KeyID              string       `json:"keyId"`
			SigningKeyID       string       `json:"signingKeyId"`
			BindingVersion     int          `json:"bindingVersion"`
			BindingSignature   string       `json:"bindingSignature"`
			SigningPublicJWK   okpPublicJWK `json:"signingPublicJwk"`
			SigningFingerprint string       `json:"signingFingerprint"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(directoryResponse.Body).Decode(&directory); err != nil {
		t.Fatal(err)
	}
	if directoryResponse.StatusCode != http.StatusOK || len(directory.Keys) != 1 || directory.Keys[0].KeyID != exchangeRegistered.KeyID ||
		directory.Keys[0].SigningKeyID != recipientSigningRegistered.KeyID || directory.Keys[0].BindingVersion != 1 ||
		directory.Keys[0].BindingSignature != bindingSignature || directory.Keys[0].SigningPublicJWK.X != base64.RawURLEncoding.EncodeToString(recipientSigningPublic) ||
		directory.Keys[0].SigningFingerprint == "" {
		t.Fatalf("unexpected exchange key directory response: status=%d body=%+v", directoryResponse.StatusCode, directory)
	}
	claimResponse := authenticatedJSON(t, testServer.URL+"/api/share-recipients/"+recipient.ID+"/prekeys/claim", "sender-session", map[string]any{})
	defer claimResponse.Body.Close()
	var claim struct {
		ClaimToken string `json:"claimToken"`
		Keys       []struct {
			KeyID string `json:"keyId"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(claimResponse.Body).Decode(&claim); err != nil {
		t.Fatal(err)
	}
	if claimResponse.StatusCode != http.StatusOK || claim.ClaimToken == "" || len(claim.Keys) != 1 {
		t.Fatalf("unexpected prekey claim: status=%d body=%+v", claimResponse.StatusCode, claim)
	}
	secondClaimResponse := authenticatedJSON(t, testServer.URL+"/api/share-recipients/"+recipient.ID+"/prekeys/claim", "sender-session", map[string]any{})
	defer secondClaimResponse.Body.Close()
	var secondClaim struct {
		ClaimToken string `json:"claimToken"`
		Keys       []struct {
			KeyID string `json:"keyId"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(secondClaimResponse.Body).Decode(&secondClaim); err != nil {
		t.Fatal(err)
	}
	if secondClaimResponse.StatusCode != http.StatusOK || secondClaim.ClaimToken != claim.ClaimToken || len(secondClaim.Keys) != 1 || secondClaim.Keys[0].KeyID != claim.Keys[0].KeyID {
		t.Fatalf("prekey claim was not idempotent: first=%+v second=%+v", claim, secondClaim)
	}
	ephemeralPrivate, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := shareRequest{
		Encrypted:          true,
		Payload:            base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
		IV:                 base64.RawURLEncoding.EncodeToString(make([]byte, 12)),
		KeyID:              signingRegistered.KeyID,
		SenderUserID:       sender.ID,
		SignatureVersion:   3,
		CryptoSuite:        encryptedCryptoSuite,
		RecipientUserID:    recipient.ID,
		EphemeralPublicJWK: okpPublicJWK{Kty: "OKP", Crv: "X25519", X: base64.RawURLEncoding.EncodeToString(ephemeralPrivate.PublicKey().Bytes())},
		KeyEnvelopes: []keyEnvelope{{
			KeyID:      claim.Keys[0].KeyID,
			Salt:       base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
			IV:         base64.RawURLEncoding.EncodeToString(make([]byte, 12)),
			WrappedKey: base64.RawURLEncoding.EncodeToString(make([]byte, 48)),
		}},
		ExpiresAt:        now.Add(30 * time.Minute).Format(time.RFC3339Nano),
		PrekeyClaimToken: claim.ClaimToken,
	}
	request.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(signingPrivate, []byte(modernShareSigningInput(request))))
	createdResponse := authenticatedJSON(t, testServer.URL+"/api/shares", "sender-session", request)
	defer createdResponse.Body.Close()
	if createdResponse.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(createdResponse.Body)
		t.Fatalf("encrypted share creation returned %d: %s", createdResponse.StatusCode, body)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(createdResponse.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	replayResponse := authenticatedJSON(t, testServer.URL+"/api/shares", "sender-session", request)
	defer replayResponse.Body.Close()
	if replayResponse.StatusCode != http.StatusConflict {
		body, _ := io.ReadAll(replayResponse.Body)
		t.Fatalf("consumed one-time prekey replay returned %d: %s", replayResponse.StatusCode, body)
	}
	if response, err := http.Get(testServer.URL + "/api/shares/" + created.ID); err != nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous encrypted share fetch = %v, %v", response, err)
	} else {
		response.Body.Close()
	}
	if response := authenticatedGet(t, testServer.URL+"/api/shares/"+created.ID, "sender-session"); response.StatusCode != http.StatusForbidden {
		response.Body.Close()
		t.Fatalf("sender encrypted share fetch returned %d", response.StatusCode)
	} else {
		response.Body.Close()
	}
	if response := authenticatedGet(t, testServer.URL+"/api/shares/"+created.ID, "recipient-session"); response.StatusCode != http.StatusOK {
		response.Body.Close()
		t.Fatalf("recipient encrypted share fetch returned %d", response.StatusCode)
	} else {
		response.Body.Close()
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

func authenticatedGet(t *testing.T, endpoint, token string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
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
		CPOAuthAuthorizeURL: "https://www.cpoauth.com/oauth/authorize", CPOAuthTokenURL: "https://www.cpoauth.com/api/oauth/token",
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
