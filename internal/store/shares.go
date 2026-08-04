package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func (s *Store) RegisterSigningKey(ctx context.Context, key SigningKey) (SigningKey, error) {
	var existing SigningKey
	var createdMS int64
	err := s.db.QueryRowContext(ctx, `SELECT id, user_id, public_jwk, fingerprint, created_at FROM user_keys WHERE user_id = ? AND fingerprint = ?`, key.UserID, key.Fingerprint).
		Scan(&existing.ID, &existing.UserID, &existing.PublicJWK, &existing.Fingerprint, &createdMS)
	if err == nil {
		existing.CreatedAt = time.UnixMilli(createdMS).UTC()
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return SigningKey{}, err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO user_keys (id, user_id, public_jwk, fingerprint, created_at) VALUES (?, ?, ?, ?, ?)`,
		key.ID, key.UserID, key.PublicJWK, key.Fingerprint, key.CreatedAt.UTC().UnixMilli())
	return key, err
}

func (s *Store) SigningKey(ctx context.Context, userID, keyID string) (SigningKey, error) {
	var key SigningKey
	var createdMS int64
	err := s.db.QueryRowContext(ctx, `SELECT id, user_id, public_jwk, fingerprint, created_at FROM user_keys WHERE id = ? AND user_id = ?`, keyID, userID).
		Scan(&key.ID, &key.UserID, &key.PublicJWK, &key.Fingerprint, &createdMS)
	if err != nil {
		return SigningKey{}, err
	}
	key.CreatedAt = time.UnixMilli(createdMS).UTC()
	return key, nil
}

func (s *Store) CreateShare(ctx context.Context, share Share, userID string) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO shares (id, user_id, key_id, encrypted, payload, iv, signature, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, share.ID, userID, share.KeyID, share.Encrypted, share.Payload, share.IV,
		share.Signature, share.CreatedAt.UTC().UnixMilli(), share.ExpiresAt.UTC().UnixMilli())
	return err
}

func (s *Store) Share(ctx context.Context, id string, now time.Time) (Share, error) {
	var share Share
	var encrypted int
	var createdMS, expiresMS int64
	var signerLast sql.NullInt64
	err := s.db.QueryRowContext(ctx, `
SELECT s.id, s.encrypted, s.payload, s.iv, s.signature, s.created_at, s.expires_at,
       u.id, u.username, u.display_name, u.avatar_url, u.total_flights, u.last_flight_at,
       k.id, k.public_jwk, k.fingerprint
FROM shares s
JOIN users u ON u.id = s.user_id
JOIN user_keys k ON k.id = s.key_id
WHERE s.id = ? AND s.expires_at > ?`, id, now.UTC().UnixMilli()).Scan(
		&share.ID, &encrypted, &share.Payload, &share.IV, &share.Signature, &createdMS, &expiresMS,
		&share.Signer.ID, &share.Signer.Username, &share.Signer.DisplayName, &share.Signer.AvatarURL,
		&share.Signer.TotalFlights, &signerLast, &share.KeyID, &share.PublicJWK, &share.Fingerprint)
	if err != nil {
		return Share{}, err
	}
	share.Encrypted = encrypted == 1
	share.CreatedAt = time.UnixMilli(createdMS).UTC()
	share.ExpiresAt = time.UnixMilli(expiresMS).UTC()
	share.Signer.LastFlightAt = nullTime(signerLast)
	return share, nil
}
