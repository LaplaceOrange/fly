package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db       *sql.DB
	location *time.Location
	flightMu sync.Mutex
	keyMu    sync.Mutex
}

func Open(path string, location *time.Location) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create database directory: %w", err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dsn := "file:" + filepath.ToSlash(abs) + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	db.SetConnMaxIdleTime(5 * time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	store := &Store{db: db, location: location}
	if err := store.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *Store) migrate(ctx context.Context) error {
	const schema = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  display_name TEXT NOT NULL,
  avatar_url TEXT NOT NULL DEFAULT '',
  total_flights INTEGER NOT NULL DEFAULT 0,
  last_flight_at INTEGER,
  first_login_at INTEGER NOT NULL,
  last_login_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS flights (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS user_keys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  algorithm TEXT NOT NULL DEFAULT 'ECDSA-P256-SHA256',
  public_jwk TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  device_label TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL DEFAULT 0,
  revoked_at INTEGER,
  UNIQUE(user_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS user_exchange_keys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  public_jwk TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  signing_key_id TEXT NOT NULL DEFAULT '',
  binding_version INTEGER NOT NULL DEFAULT 0,
  binding_signature TEXT NOT NULL DEFAULT '',
  device_label TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL DEFAULT 0,
  revoked_at INTEGER,
  UNIQUE(user_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS user_prekeys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  exchange_key_id TEXT NOT NULL REFERENCES user_exchange_keys(id) ON DELETE CASCADE,
  signing_key_id TEXT NOT NULL REFERENCES user_keys(id) ON DELETE CASCADE,
  public_jwk TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  binding_version INTEGER NOT NULL,
  binding_signature TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  claimed_by_user_id TEXT NOT NULL DEFAULT '',
  claim_token TEXT NOT NULL DEFAULT '',
  claim_token_hash TEXT NOT NULL DEFAULT '',
  claim_expires_at INTEGER,
  used_at INTEGER,
  retain_until INTEGER,
  UNIQUE(user_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS shares (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  key_id TEXT NOT NULL REFERENCES user_keys(id) ON DELETE RESTRICT,
  encrypted INTEGER NOT NULL,
  payload TEXT NOT NULL,
  iv TEXT NOT NULL DEFAULT '',
  signature TEXT NOT NULL,
  signature_version INTEGER NOT NULL DEFAULT 1,
  crypto_suite TEXT NOT NULL DEFAULT 'legacy-aes-256-gcm+ecdsa-p256-sha256',
  recipient_user_id TEXT NOT NULL DEFAULT '',
  ephemeral_public_jwk TEXT NOT NULL DEFAULT '',
  key_envelopes TEXT NOT NULL DEFAULT '[]',
  signed_expires_at TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_flights_created_at ON flights(created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_flights_user_created ON flights(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_users_total ON users(total_flights DESC, id ASC);
CREATE INDEX IF NOT EXISTS idx_users_last_flight ON users(last_flight_at DESC, id ASC);
CREATE INDEX IF NOT EXISTS idx_shares_expires ON shares(expires_at);
CREATE INDEX IF NOT EXISTS idx_exchange_keys_user ON user_exchange_keys(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_prekeys_available ON user_prekeys(user_id, exchange_key_id, used_at, claim_expires_at, created_at);
`
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return err
	}
	columns := []struct {
		table      string
		name       string
		definition string
	}{
		{"user_keys", "algorithm", "TEXT NOT NULL DEFAULT 'ECDSA-P256-SHA256'"},
		{"user_keys", "device_label", "TEXT NOT NULL DEFAULT ''"},
		{"user_keys", "last_seen_at", "INTEGER NOT NULL DEFAULT 0"},
		{"user_keys", "revoked_at", "INTEGER"},
		{"user_exchange_keys", "signing_key_id", "TEXT NOT NULL DEFAULT ''"},
		{"user_exchange_keys", "binding_version", "INTEGER NOT NULL DEFAULT 0"},
		{"user_exchange_keys", "binding_signature", "TEXT NOT NULL DEFAULT ''"},
		{"user_exchange_keys", "device_label", "TEXT NOT NULL DEFAULT ''"},
		{"user_exchange_keys", "last_seen_at", "INTEGER NOT NULL DEFAULT 0"},
		{"user_exchange_keys", "revoked_at", "INTEGER"},
		{"shares", "signature_version", "INTEGER NOT NULL DEFAULT 1"},
		{"shares", "crypto_suite", "TEXT NOT NULL DEFAULT 'legacy-aes-256-gcm+ecdsa-p256-sha256'"},
		{"shares", "recipient_user_id", "TEXT NOT NULL DEFAULT ''"},
		{"shares", "ephemeral_public_jwk", "TEXT NOT NULL DEFAULT ''"},
		{"shares", "key_envelopes", "TEXT NOT NULL DEFAULT '[]'"},
		{"shares", "signed_expires_at", "TEXT NOT NULL DEFAULT ''"},
		{"user_prekeys", "claim_token", "TEXT NOT NULL DEFAULT ''"},
		{"user_prekeys", "retain_until", "INTEGER"},
	}
	for _, column := range columns {
		if err := s.ensureColumn(ctx, column.table, column.name, column.definition); err != nil {
			return err
		}
	}
	_, err := s.db.ExecContext(ctx, `
CREATE INDEX IF NOT EXISTS idx_shares_recipient ON shares(recipient_user_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_prekeys_available ON user_prekeys(user_id, exchange_key_id, used_at, claim_expires_at, created_at);
CREATE INDEX IF NOT EXISTS idx_exchange_keys_active ON user_exchange_keys(user_id, revoked_at, created_at DESC);
`)
	return err
}

func (s *Store) ensureColumn(ctx context.Context, table, column, definition string) error {
	rows, err := s.db.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return err
	}
	found := false
	for rows.Next() {
		var cid int
		var name, columnType string
		var notNull, primaryKey int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			return err
		}
		if name == column {
			found = true
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if found {
		return nil
	}
	_, err = s.db.ExecContext(ctx, "ALTER TABLE "+table+" ADD COLUMN "+column+" "+definition)
	return err
}

func (s *Store) CleanupExpiredSessions(ctx context.Context, interval time.Duration, logger *slog.Logger) {
	cleanup := func() {
		now := time.Now().UTC().UnixMilli()
		if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, now); err != nil && !errors.Is(err, context.Canceled) {
			logger.Warn("session cleanup failed", "error", err)
		}
		if _, err := s.db.ExecContext(ctx, `DELETE FROM shares WHERE expires_at <= ?`, now); err != nil && !errors.Is(err, context.Canceled) {
			logger.Warn("share cleanup failed", "error", err)
		}
		if _, err := s.db.ExecContext(ctx, `DELETE FROM user_prekeys WHERE used_at IS NOT NULL AND retain_until <= ?`, now); err != nil && !errors.Is(err, context.Canceled) {
			logger.Warn("prekey cleanup failed", "error", err)
		}
	}
	cleanup()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cleanup()
		}
	}
}
