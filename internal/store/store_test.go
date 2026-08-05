package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConcurrentTakeoffAllowsOnlyOneFlight(t *testing.T) {
	t.Parallel()
	db := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	user, err := db.UpsertUser(ctx, User{ID: "user-1", Username: "pilot", DisplayName: "Pilot"}, now)
	if err != nil {
		t.Fatal(err)
	}

	var successes atomic.Int32
	var limited atomic.Int32
	var wait sync.WaitGroup
	for range 20 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, _, err := db.CreateFlight(ctx, user.ID, now, 10*time.Minute)
			if err == nil {
				successes.Add(1)
				return
			}
			var rateError *RateLimitError
			if errors.As(err, &rateError) {
				limited.Add(1)
				return
			}
			t.Errorf("unexpected error: %v", err)
		}()
	}
	wait.Wait()
	if successes.Load() != 1 || limited.Load() != 19 {
		t.Fatalf("got %d successes and %d limited requests", successes.Load(), limited.Load())
	}
	dashboard, err := db.Dashboard(ctx, "24h", now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if dashboard.Summary.TotalFlights != 1 || dashboard.Revision != 1 {
		t.Fatalf("unexpected dashboard: %+v", dashboard)
	}
}

func TestSessionAndSharePersistence(t *testing.T) {
	t.Parallel()
	db := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	user, err := db.UpsertUser(ctx, User{ID: "user-2", Username: "flyer", DisplayName: "Flyer"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.CreateSession(ctx, SessionHash("secret-token"), user.ID, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	loaded, err := db.UserBySession(ctx, SessionHash("secret-token"), now)
	if err != nil || loaded.ID != user.ID {
		t.Fatalf("session lookup failed: %+v %v", loaded, err)
	}
	key, err := db.RegisterSigningKey(ctx, SigningKey{ID: "key-1", UserID: user.ID, PublicJWK: `{"kty":"EC"}`, Fingerprint: "fingerprint", CreatedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	share := Share{ID: "share-1", Encrypted: true, Payload: "ciphertext", IV: "iv", Signature: "signature", KeyID: key.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := db.CreateShare(ctx, share, user.ID); err != nil {
		t.Fatal(err)
	}
	loadedShare, err := db.Share(ctx, share.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if !loadedShare.Encrypted || loadedShare.Payload != share.Payload || loadedShare.Signer.ID != user.ID {
		t.Fatalf("unexpected share: %+v", loadedShare)
	}
}

func TestExchangeKeysRecipientsAndModernEnvelopePersistence(t *testing.T) {
	t.Parallel()
	db := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Millisecond)
	sender, err := db.UpsertUser(ctx, User{ID: "sender", Username: "sender", DisplayName: "Sender"}, now)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := db.UpsertUser(ctx, User{ID: "recipient", Username: "recipient", DisplayName: "Recipient"}, now)
	if err != nil {
		t.Fatal(err)
	}
	signing, err := db.RegisterSigningKey(ctx, SigningKey{
		ID: "ed-key", UserID: sender.ID, Algorithm: "Ed25519", PublicJWK: `{"kty":"OKP","crv":"Ed25519","x":"x"}`,
		Fingerprint: "ed-fingerprint", CreatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.RegisterExchangeKey(ctx, ExchangeKey{
		ID: "x-key", UserID: recipient.ID, PublicJWK: `{"kty":"OKP","crv":"X25519","x":"x"}`,
		Fingerprint: "x-fingerprint", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	recipients, err := db.ShareRecipients(ctx, sender.ID, 100)
	if err != nil || len(recipients) != 1 || recipients[0].ID != recipient.ID || recipients[0].DeviceCount != 1 {
		t.Fatalf("unexpected recipients: %+v (%v)", recipients, err)
	}
	share := Share{
		ID: "modern-share", Encrypted: true, Payload: "ciphertext", IV: "iv", Signature: "signature",
		SignatureVersion: 2, CryptoSuite: "X25519-HKDF-SHA256-AES-256-GCM+Ed25519",
		RecipientUserID: recipient.ID, EphemeralPublicJWK: `{"kty":"OKP"}`, KeyEnvelopes: `[{"keyId":"x-key"}]`,
		KeyID: signing.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := db.CreateShare(ctx, share, sender.ID); err != nil {
		t.Fatal(err)
	}
	loaded, err := db.Share(ctx, share.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.SignatureVersion != 2 || loaded.RecipientUserID != recipient.ID || loaded.SigningAlgorithm != "Ed25519" || loaded.KeyEnvelopes != share.KeyEnvelopes {
		t.Fatalf("unexpected modern share: %+v", loaded)
	}
}

func TestExchangeKeyDeviceLimit(t *testing.T) {
	t.Parallel()
	db := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	user, err := db.UpsertUser(ctx, User{ID: "key-limit-user", Username: "keys", DisplayName: "Keys"}, now)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 32; index++ {
		if _, err := db.RegisterExchangeKey(ctx, ExchangeKey{
			ID: fmt.Sprintf("key-%02d", index), UserID: user.ID, PublicJWK: fmt.Sprintf(`{"x":%d}`, index),
			Fingerprint: fmt.Sprintf("fingerprint-%02d", index), CreatedAt: now.Add(time.Duration(index) * time.Second),
		}); err != nil {
			t.Fatalf("register exchange key %d: %v", index, err)
		}
	}
	_, err = db.RegisterExchangeKey(ctx, ExchangeKey{
		ID: "key-over-limit", UserID: user.ID, PublicJWK: `{"x":32}`, Fingerprint: "fingerprint-over-limit", CreatedAt: now,
	})
	if !errors.Is(err, ErrDeviceKeyLimit) {
		t.Fatalf("33rd exchange key error = %v, want ErrDeviceKeyLimit", err)
	}
}

func TestMigrationUpgradesLegacyShareSchema(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "legacy.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	legacySchema := `
CREATE TABLE users (
  id TEXT PRIMARY KEY, username TEXT NOT NULL, display_name TEXT NOT NULL, avatar_url TEXT NOT NULL DEFAULT '',
  total_flights INTEGER NOT NULL DEFAULT 0, last_flight_at INTEGER, first_login_at INTEGER NOT NULL,
  last_login_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE user_keys (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), public_jwk TEXT NOT NULL,
  fingerprint TEXT NOT NULL, created_at INTEGER NOT NULL, UNIQUE(user_id, fingerprint)
);
CREATE TABLE shares (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), key_id TEXT NOT NULL REFERENCES user_keys(id),
  encrypted INTEGER NOT NULL, payload TEXT NOT NULL, iv TEXT NOT NULL DEFAULT '', signature TEXT NOT NULL,
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
);`
	if _, err := raw.Exec(legacySchema); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := Open(path, time.FixedZone("CST", 8*60*60))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	wantColumns := map[string]bool{
		"signature_version": false, "crypto_suite": false, "recipient_user_id": false,
		"ephemeral_public_jwk": false, "key_envelopes": false,
	}
	rows, err := db.db.Query(`PRAGMA table_info(shares)`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		if _, expected := wantColumns[name]; expected {
			wantColumns[name] = true
		}
	}
	rows.Close()
	for column, found := range wantColumns {
		if !found {
			t.Fatalf("migration did not add shares.%s", column)
		}
	}
	keyRows, err := db.db.Query(`PRAGMA table_info(user_keys)`)
	if err != nil {
		t.Fatal(err)
	}
	algorithmFound := false
	for keyRows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := keyRows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			keyRows.Close()
			t.Fatal(err)
		}
		algorithmFound = algorithmFound || name == "algorithm"
	}
	keyRows.Close()
	if !algorithmFound {
		t.Fatal("migration did not add user_keys.algorithm")
	}
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "test.db"), time.FixedZone("CST", 8*60*60))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
