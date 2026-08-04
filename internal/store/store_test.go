package store

import (
	"context"
	"errors"
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

func openTestStore(t *testing.T) *Store {
	t.Helper()
	db, err := Open(filepath.Join(t.TempDir(), "test.db"), time.FixedZone("CST", 8*60*60))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
