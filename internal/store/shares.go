package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func (s *Store) RegisterSigningKey(ctx context.Context, key SigningKey) (SigningKey, error) {
	if key.Algorithm == "" {
		key.Algorithm = "ECDSA-P256-SHA256"
	}
	var existing SigningKey
	var createdMS int64
	err := s.db.QueryRowContext(ctx, `SELECT id, user_id, algorithm, public_jwk, fingerprint, created_at FROM user_keys WHERE user_id = ? AND fingerprint = ?`, key.UserID, key.Fingerprint).
		Scan(&existing.ID, &existing.UserID, &existing.Algorithm, &existing.PublicJWK, &existing.Fingerprint, &createdMS)
	if err == nil {
		existing.CreatedAt = time.UnixMilli(createdMS).UTC()
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return SigningKey{}, err
	}
	result, err := s.db.ExecContext(ctx, `
INSERT INTO user_keys (id, user_id, algorithm, public_jwk, fingerprint, created_at)
SELECT ?, ?, ?, ?, ?, ?
WHERE (SELECT COUNT(*) FROM user_keys WHERE user_id = ?) < 32`,
		key.ID, key.UserID, key.Algorithm, key.PublicJWK, key.Fingerprint, key.CreatedAt.UTC().UnixMilli(), key.UserID)
	if err != nil {
		return SigningKey{}, err
	}
	if changed, err := result.RowsAffected(); err != nil {
		return SigningKey{}, err
	} else if changed == 0 {
		return SigningKey{}, ErrDeviceKeyLimit
	}
	return key, nil
}

func (s *Store) SigningKey(ctx context.Context, userID, keyID string) (SigningKey, error) {
	var key SigningKey
	var createdMS int64
	err := s.db.QueryRowContext(ctx, `SELECT id, user_id, algorithm, public_jwk, fingerprint, created_at FROM user_keys WHERE id = ? AND user_id = ?`, keyID, userID).
		Scan(&key.ID, &key.UserID, &key.Algorithm, &key.PublicJWK, &key.Fingerprint, &createdMS)
	if err != nil {
		return SigningKey{}, err
	}
	key.CreatedAt = time.UnixMilli(createdMS).UTC()
	return key, nil
}

func (s *Store) RegisterExchangeKey(ctx context.Context, key ExchangeKey) (ExchangeKey, error) {
	var existing ExchangeKey
	var createdMS int64
	err := s.db.QueryRowContext(ctx, `SELECT id, user_id, public_jwk, fingerprint, created_at FROM user_exchange_keys WHERE user_id = ? AND fingerprint = ?`, key.UserID, key.Fingerprint).
		Scan(&existing.ID, &existing.UserID, &existing.PublicJWK, &existing.Fingerprint, &createdMS)
	if err == nil {
		existing.CreatedAt = time.UnixMilli(createdMS).UTC()
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return ExchangeKey{}, err
	}
	result, err := s.db.ExecContext(ctx, `
INSERT INTO user_exchange_keys (id, user_id, public_jwk, fingerprint, created_at)
SELECT ?, ?, ?, ?, ?
WHERE (SELECT COUNT(*) FROM user_exchange_keys WHERE user_id = ?) < 32`,
		key.ID, key.UserID, key.PublicJWK, key.Fingerprint, key.CreatedAt.UTC().UnixMilli(), key.UserID)
	if err != nil {
		return ExchangeKey{}, err
	}
	if changed, err := result.RowsAffected(); err != nil {
		return ExchangeKey{}, err
	} else if changed == 0 {
		return ExchangeKey{}, ErrDeviceKeyLimit
	}
	return key, nil
}

func (s *Store) ExchangeKeys(ctx context.Context, userID string) ([]ExchangeKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, user_id, public_jwk, fingerprint, created_at FROM user_exchange_keys WHERE user_id = ? ORDER BY created_at DESC LIMIT 32`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := make([]ExchangeKey, 0, 4)
	for rows.Next() {
		var key ExchangeKey
		var createdMS int64
		if err := rows.Scan(&key.ID, &key.UserID, &key.PublicJWK, &key.Fingerprint, &createdMS); err != nil {
			return nil, err
		}
		key.CreatedAt = time.UnixMilli(createdMS).UTC()
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (s *Store) ShareRecipients(ctx context.Context, excludeUserID string, limit int) ([]ShareRecipient, error) {
	if limit < 1 || limit > 100 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT u.id, u.username, u.display_name, u.avatar_url, u.total_flights, u.last_flight_at, COUNT(k.id)
FROM users u JOIN user_exchange_keys k ON k.user_id = u.id
WHERE u.id <> ?
GROUP BY u.id
ORDER BY u.display_name COLLATE NOCASE, u.id
LIMIT ?`, excludeUserID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	recipients := make([]ShareRecipient, 0, limit)
	for rows.Next() {
		var recipient ShareRecipient
		var last sql.NullInt64
		if err := rows.Scan(&recipient.ID, &recipient.Username, &recipient.DisplayName, &recipient.AvatarURL, &recipient.TotalFlights, &last, &recipient.DeviceCount); err != nil {
			return nil, err
		}
		recipient.LastFlightAt = nullTime(last)
		recipients = append(recipients, recipient)
	}
	return recipients, rows.Err()
}

func (s *Store) CreateShare(ctx context.Context, share Share, userID string) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO shares (id, user_id, key_id, encrypted, payload, iv, signature, signature_version, crypto_suite, recipient_user_id, ephemeral_public_jwk, key_envelopes, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, share.ID, userID, share.KeyID, share.Encrypted, share.Payload, share.IV,
		share.Signature, share.SignatureVersion, share.CryptoSuite, share.RecipientUserID, share.EphemeralPublicJWK, share.KeyEnvelopes,
		share.CreatedAt.UTC().UnixMilli(), share.ExpiresAt.UTC().UnixMilli())
	return err
}

func (s *Store) Share(ctx context.Context, id string, now time.Time) (Share, error) {
	var share Share
	var encrypted int
	var createdMS, expiresMS int64
	var signerLast sql.NullInt64
	err := s.db.QueryRowContext(ctx, `
SELECT s.id, s.encrypted, s.payload, s.iv, s.signature, s.signature_version, s.crypto_suite,
       s.recipient_user_id, s.ephemeral_public_jwk, s.key_envelopes, s.created_at, s.expires_at,
       u.id, u.username, u.display_name, u.avatar_url, u.total_flights, u.last_flight_at,
       k.id, k.algorithm, k.public_jwk, k.fingerprint
FROM shares s
JOIN users u ON u.id = s.user_id
JOIN user_keys k ON k.id = s.key_id
WHERE s.id = ? AND s.expires_at > ?`, id, now.UTC().UnixMilli()).Scan(
		&share.ID, &encrypted, &share.Payload, &share.IV, &share.Signature, &share.SignatureVersion, &share.CryptoSuite,
		&share.RecipientUserID, &share.EphemeralPublicJWK, &share.KeyEnvelopes, &createdMS, &expiresMS,
		&share.Signer.ID, &share.Signer.Username, &share.Signer.DisplayName, &share.Signer.AvatarURL,
		&share.Signer.TotalFlights, &signerLast, &share.KeyID, &share.SigningAlgorithm, &share.PublicJWK, &share.Fingerprint)
	if err != nil {
		return Share{}, err
	}
	share.Encrypted = encrypted == 1
	share.CreatedAt = time.UnixMilli(createdMS).UTC()
	share.ExpiresAt = time.UnixMilli(expiresMS).UTC()
	share.Signer.LastFlightAt = nullTime(signerLast)
	return share, nil
}
