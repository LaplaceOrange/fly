package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"
)

func (s *Store) RegisterSigningKey(ctx context.Context, key SigningKey) (SigningKey, error) {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	if key.Algorithm == "" {
		key.Algorithm = "ECDSA-P256-SHA256"
	}
	var existing SigningKey
	if key.LastSeenAt.IsZero() {
		key.LastSeenAt = key.CreatedAt
	}
	var createdMS, lastSeenMS int64
	var revokedMS sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT id, user_id, algorithm, public_jwk, fingerprint, device_label, created_at, last_seen_at, revoked_at FROM user_keys WHERE user_id = ? AND fingerprint = ?`, key.UserID, key.Fingerprint).
		Scan(&existing.ID, &existing.UserID, &existing.Algorithm, &existing.PublicJWK, &existing.Fingerprint, &existing.DeviceLabel, &createdMS, &lastSeenMS, &revokedMS)
	if err == nil {
		if revokedMS.Valid {
			return SigningKey{}, ErrKeyRevoked
		}
		if _, err := s.db.ExecContext(ctx, `UPDATE user_keys SET last_seen_at = ?, device_label = ? WHERE id = ? AND user_id = ?`, key.LastSeenAt.UTC().UnixMilli(), key.DeviceLabel, existing.ID, key.UserID); err != nil {
			return SigningKey{}, err
		}
		existing.CreatedAt = time.UnixMilli(createdMS).UTC()
		existing.LastSeenAt = key.LastSeenAt.UTC()
		existing.DeviceLabel = key.DeviceLabel
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return SigningKey{}, err
	}
	result, err := s.db.ExecContext(ctx, `
INSERT INTO user_keys (id, user_id, algorithm, public_jwk, fingerprint, device_label, created_at, last_seen_at)
SELECT ?, ?, ?, ?, ?, ?, ?, ?
WHERE (SELECT COUNT(*) FROM user_keys WHERE user_id = ? AND revoked_at IS NULL) < 32
  AND (SELECT COUNT(*) FROM user_keys WHERE user_id = ?) < 256`,
		key.ID, key.UserID, key.Algorithm, key.PublicJWK, key.Fingerprint, key.DeviceLabel,
		key.CreatedAt.UTC().UnixMilli(), key.LastSeenAt.UTC().UnixMilli(), key.UserID, key.UserID)
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
	var createdMS, lastSeenMS int64
	var revokedMS sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT id, user_id, algorithm, public_jwk, fingerprint, device_label, created_at, last_seen_at, revoked_at FROM user_keys WHERE id = ? AND user_id = ?`, keyID, userID).
		Scan(&key.ID, &key.UserID, &key.Algorithm, &key.PublicJWK, &key.Fingerprint, &key.DeviceLabel, &createdMS, &lastSeenMS, &revokedMS)
	if err != nil {
		return SigningKey{}, err
	}
	key.CreatedAt = time.UnixMilli(createdMS).UTC()
	key.LastSeenAt = time.UnixMilli(lastSeenMS).UTC()
	key.RevokedAt = nullTime(revokedMS)
	return key, nil
}

func (s *Store) RegisterExchangeKey(ctx context.Context, key ExchangeKey) (ExchangeKey, error) {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	var activeSigningKey int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_keys WHERE id = ? AND user_id = ? AND revoked_at IS NULL`, key.SigningKeyID, key.UserID).Scan(&activeSigningKey); err != nil {
		return ExchangeKey{}, err
	}
	if activeSigningKey != 1 {
		return ExchangeKey{}, ErrKeyRevoked
	}
	var existing ExchangeKey
	if key.LastSeenAt.IsZero() {
		key.LastSeenAt = key.CreatedAt
	}
	var createdMS, lastSeenMS int64
	var revokedMS sql.NullInt64
	err := s.db.QueryRowContext(ctx, `
SELECT id, user_id, public_jwk, fingerprint, signing_key_id, binding_version, binding_signature, device_label, created_at, last_seen_at, revoked_at
FROM user_exchange_keys WHERE user_id = ? AND fingerprint = ?`, key.UserID, key.Fingerprint).
		Scan(&existing.ID, &existing.UserID, &existing.PublicJWK, &existing.Fingerprint, &existing.SigningKeyID,
			&existing.BindingVersion, &existing.BindingSignature, &existing.DeviceLabel, &createdMS, &lastSeenMS, &revokedMS)
	if err == nil {
		if revokedMS.Valid {
			return ExchangeKey{}, ErrKeyRevoked
		}
		if _, err := s.db.ExecContext(ctx, `
UPDATE user_exchange_keys SET public_jwk = ?, signing_key_id = ?, binding_version = ?, binding_signature = ?, device_label = ?, last_seen_at = ?
WHERE id = ? AND user_id = ?`, key.PublicJWK, key.SigningKeyID, key.BindingVersion, key.BindingSignature,
			key.DeviceLabel, key.LastSeenAt.UTC().UnixMilli(), existing.ID, key.UserID); err != nil {
			return ExchangeKey{}, err
		}
		existing.PublicJWK = key.PublicJWK
		existing.SigningKeyID = key.SigningKeyID
		existing.BindingVersion = key.BindingVersion
		existing.BindingSignature = key.BindingSignature
		existing.DeviceLabel = key.DeviceLabel
		existing.CreatedAt = time.UnixMilli(createdMS).UTC()
		existing.LastSeenAt = key.LastSeenAt.UTC()
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return ExchangeKey{}, err
	}
	result, err := s.db.ExecContext(ctx, `
INSERT INTO user_exchange_keys (id, user_id, public_jwk, fingerprint, signing_key_id, binding_version, binding_signature, device_label, created_at, last_seen_at)
SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
WHERE (SELECT COUNT(*) FROM user_exchange_keys WHERE user_id = ? AND binding_version = 1 AND revoked_at IS NULL) < 32
  AND (SELECT COUNT(*) FROM user_exchange_keys WHERE user_id = ?) < 256`,
		key.ID, key.UserID, key.PublicJWK, key.Fingerprint, key.SigningKeyID, key.BindingVersion, key.BindingSignature,
		key.DeviceLabel, key.CreatedAt.UTC().UnixMilli(), key.LastSeenAt.UTC().UnixMilli(), key.UserID, key.UserID)
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
	rows, err := s.db.QueryContext(ctx, `
SELECT x.id, x.user_id, x.public_jwk, x.fingerprint, x.signing_key_id, x.binding_version, x.binding_signature,
       k.public_jwk, k.fingerprint, x.created_at
FROM user_exchange_keys x
JOIN user_keys k ON k.id = x.signing_key_id AND k.user_id = x.user_id AND k.algorithm = 'Ed25519'
WHERE x.user_id = ? AND x.binding_version = 1 AND x.binding_signature <> '' AND x.revoked_at IS NULL AND k.revoked_at IS NULL
ORDER BY x.created_at DESC LIMIT 32`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := make([]ExchangeKey, 0, 4)
	for rows.Next() {
		var key ExchangeKey
		var createdMS int64
		if err := rows.Scan(&key.ID, &key.UserID, &key.PublicJWK, &key.Fingerprint, &key.SigningKeyID,
			&key.BindingVersion, &key.BindingSignature, &key.SigningPublicJWK, &key.SigningFingerprint, &createdMS); err != nil {
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
FROM users u
JOIN user_exchange_keys k ON k.user_id = u.id AND k.binding_version = 1 AND k.binding_signature <> '' AND k.revoked_at IS NULL
JOIN user_keys sk ON sk.id = k.signing_key_id AND sk.user_id = k.user_id AND sk.algorithm = 'Ed25519'
WHERE u.id <> ? AND sk.revoked_at IS NULL
  AND EXISTS (
    SELECT 1 FROM user_prekeys p
    WHERE p.exchange_key_id = k.id AND p.used_at IS NULL
      AND (p.claim_expires_at IS NULL OR p.claim_expires_at <= ?)
  )
GROUP BY u.id
ORDER BY u.display_name COLLATE NOCASE, u.id
LIMIT ?`, excludeUserID, time.Now().UTC().UnixMilli(), limit)
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

func (s *Store) CreateShare(ctx context.Context, share Share, userID, claimToken string, prekeyIDs []string) error {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if share.Encrypted {
		nowMS := share.CreatedAt.UTC().UnixMilli()
		tokenHash := hashClaimToken(claimToken)
		for _, id := range prekeyIDs {
			result, err := tx.ExecContext(ctx, `
UPDATE user_prekeys SET used_at = ?, retain_until = ?, claim_token = '', claim_token_hash = '', claim_expires_at = NULL
WHERE id = ? AND user_id = ? AND claimed_by_user_id = ? AND claim_token_hash = ?
  AND used_at IS NULL AND claim_expires_at > ?`, nowMS, share.ExpiresAt.UTC().UnixMilli(), id, share.RecipientUserID, userID, tokenHash, nowMS)
			if err != nil {
				return err
			}
			if changed, err := result.RowsAffected(); err != nil || changed != 1 {
				return ErrPrekeyClaim
			}
		}
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO shares (id, user_id, key_id, encrypted, payload, iv, signature, signature_version, crypto_suite, recipient_user_id, ephemeral_public_jwk, key_envelopes, signed_expires_at, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, share.ID, userID, share.KeyID, share.Encrypted, share.Payload, share.IV,
		share.Signature, share.SignatureVersion, share.CryptoSuite, share.RecipientUserID, share.EphemeralPublicJWK, share.KeyEnvelopes,
		share.SignedExpiresAt, share.CreatedAt.UTC().UnixMilli(), share.ExpiresAt.UTC().UnixMilli())
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Share(ctx context.Context, id string, now time.Time) (Share, error) {
	var share Share
	var encrypted int
	var createdMS, expiresMS int64
	var signerLast sql.NullInt64
	err := s.db.QueryRowContext(ctx, `
SELECT s.id, s.encrypted, s.payload, s.iv, s.signature, s.signature_version, s.crypto_suite,
       s.recipient_user_id, s.ephemeral_public_jwk, s.key_envelopes, s.signed_expires_at, s.created_at, s.expires_at,
       u.id, u.username, u.display_name, u.avatar_url, u.total_flights, u.last_flight_at,
       k.id, k.algorithm, k.public_jwk, k.fingerprint
FROM shares s
JOIN users u ON u.id = s.user_id
JOIN user_keys k ON k.id = s.key_id AND k.user_id = s.user_id
WHERE s.id = ? AND s.expires_at > ?`, id, now.UTC().UnixMilli()).Scan(
		&share.ID, &encrypted, &share.Payload, &share.IV, &share.Signature, &share.SignatureVersion, &share.CryptoSuite,
		&share.RecipientUserID, &share.EphemeralPublicJWK, &share.KeyEnvelopes, &share.SignedExpiresAt, &createdMS, &expiresMS,
		&share.Signer.ID, &share.Signer.Username, &share.Signer.DisplayName, &share.Signer.AvatarURL,
		&share.Signer.TotalFlights, &signerLast, &share.KeyID, &share.SigningAlgorithm, &share.PublicJWK, &share.Fingerprint)
	if err != nil {
		return Share{}, err
	}
	share.Encrypted = encrypted == 1
	share.CreatedAt = time.UnixMilli(createdMS).UTC()
	share.ExpiresAt = time.UnixMilli(expiresMS).UTC()
	if share.SignedExpiresAt == "" {
		share.SignedExpiresAt = share.ExpiresAt.Format(time.RFC3339Nano)
	}
	share.Signer.LastFlightAt = nullTime(signerLast)
	return share, nil
}

func (s *Store) RegisterPrekey(ctx context.Context, key OneTimePrekey) (OneTimePrekey, error) {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	var activeDevice int
	if err := s.db.QueryRowContext(ctx, `
SELECT COUNT(*)
FROM user_exchange_keys x
JOIN user_keys k ON k.id = x.signing_key_id AND k.user_id = x.user_id
WHERE x.id = ? AND x.user_id = ? AND x.signing_key_id = ?
  AND x.revoked_at IS NULL AND k.revoked_at IS NULL`, key.ExchangeKeyID, key.UserID, key.SigningKeyID).Scan(&activeDevice); err != nil {
		return OneTimePrekey{}, err
	}
	if activeDevice != 1 {
		return OneTimePrekey{}, ErrKeyRevoked
	}
	var existing OneTimePrekey
	var createdMS int64
	err := s.db.QueryRowContext(ctx, `
SELECT id, user_id, exchange_key_id, signing_key_id, public_jwk, fingerprint, binding_version, binding_signature, created_at
FROM user_prekeys WHERE user_id = ? AND fingerprint = ?`, key.UserID, key.Fingerprint).
		Scan(&existing.ID, &existing.UserID, &existing.ExchangeKeyID, &existing.SigningKeyID, &existing.PublicJWK,
			&existing.Fingerprint, &existing.BindingVersion, &existing.BindingSignature, &createdMS)
	if err == nil {
		existing.CreatedAt = time.UnixMilli(createdMS).UTC()
		return existing, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return OneTimePrekey{}, err
	}
	result, err := s.db.ExecContext(ctx, `
INSERT INTO user_prekeys (id, user_id, exchange_key_id, signing_key_id, public_jwk, fingerprint, binding_version, binding_signature, created_at)
SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?
WHERE (SELECT COUNT(*) FROM user_prekeys WHERE user_id = ? AND used_at IS NULL) < 256`, key.ID, key.UserID, key.ExchangeKeyID, key.SigningKeyID, key.PublicJWK,
		key.Fingerprint, key.BindingVersion, key.BindingSignature, key.CreatedAt.UTC().UnixMilli(), key.UserID)
	if err != nil {
		return OneTimePrekey{}, err
	}
	if changed, err := result.RowsAffected(); err != nil {
		return OneTimePrekey{}, err
	} else if changed == 0 {
		return OneTimePrekey{}, ErrPrekeyLimit
	}
	return key, nil
}

func (s *Store) PrekeyInventory(ctx context.Context, userID, exchangeKeyID string, now time.Time) ([]string, []string, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT fingerprint, used_at FROM user_prekeys
WHERE user_id = ? AND exchange_key_id = ?
  AND (used_at IS NULL OR retain_until > ?)
ORDER BY created_at`, userID, exchangeKeyID, now.UTC().UnixMilli())
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	available := make([]string, 0, 8)
	retained := make([]string, 0, 8)
	for rows.Next() {
		var value string
		var usedAt sql.NullInt64
		if err := rows.Scan(&value, &usedAt); err != nil {
			return nil, nil, err
		}
		if usedAt.Valid {
			retained = append(retained, value)
		} else {
			available = append(available, value)
		}
	}
	return available, retained, rows.Err()
}

func (s *Store) ClaimPrekeys(ctx context.Context, recipientID, senderID, claimToken string, now time.Time) ([]OneTimePrekey, string, error) {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()
	var existingToken string
	err = tx.QueryRowContext(ctx, `
SELECT claim_token FROM user_prekeys
WHERE user_id = ? AND claimed_by_user_id = ? AND claim_token <> ''
  AND used_at IS NULL AND claim_expires_at > ?
ORDER BY claim_expires_at DESC LIMIT 1`, recipientID, senderID, now.UTC().UnixMilli()).Scan(&existingToken)
	if err == nil {
		keys, err := claimedPrekeys(ctx, tx, recipientID, senderID, existingToken, now)
		if err != nil {
			return nil, "", err
		}
		if len(keys) > 0 {
			return keys, existingToken, nil
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, "", err
	}
	rows, err := tx.QueryContext(ctx, `
SELECT x.id
FROM user_exchange_keys x
JOIN user_keys k ON k.id = x.signing_key_id AND k.user_id = x.user_id
WHERE x.user_id = ? AND x.revoked_at IS NULL AND k.revoked_at IS NULL
  AND x.binding_version = 1 AND x.binding_signature <> ''
  AND EXISTS (
    SELECT 1 FROM user_prekeys p WHERE p.exchange_key_id = x.id AND p.used_at IS NULL
      AND (p.claim_expires_at IS NULL OR p.claim_expires_at <= ?)
  )
	ORDER BY x.created_at`, recipientID, now.UTC().UnixMilli())
	if err != nil {
		return nil, "", err
	}
	var devices []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, "", err
		}
		devices = append(devices, id)
	}
	if err := rows.Close(); err != nil {
		return nil, "", err
	}
	if len(devices) == 0 {
		return nil, "", sql.ErrNoRows
	}
	expiresMS := now.Add(2 * time.Minute).UTC().UnixMilli()
	tokenHash := hashClaimToken(claimToken)
	claimed := make([]OneTimePrekey, 0, len(devices))
	for _, deviceID := range devices {
		var key OneTimePrekey
		var createdMS int64
		err := tx.QueryRowContext(ctx, `
SELECT p.id, p.user_id, p.exchange_key_id, p.signing_key_id, p.public_jwk, p.fingerprint,
       p.binding_version, p.binding_signature, x.public_jwk, x.fingerprint, x.binding_signature,
       k.public_jwk, k.fingerprint, x.device_label, p.created_at
FROM user_prekeys p
JOIN user_exchange_keys x ON x.id = p.exchange_key_id AND x.user_id = p.user_id AND x.revoked_at IS NULL
JOIN user_keys k ON k.id = p.signing_key_id AND k.user_id = p.user_id AND k.revoked_at IS NULL
WHERE p.exchange_key_id = ? AND p.used_at IS NULL AND (p.claim_expires_at IS NULL OR p.claim_expires_at <= ?)
ORDER BY p.created_at LIMIT 1`, deviceID, now.UTC().UnixMilli()).Scan(
			&key.ID, &key.UserID, &key.ExchangeKeyID, &key.SigningKeyID, &key.PublicJWK, &key.Fingerprint,
			&key.BindingVersion, &key.BindingSignature, &key.ExchangePublicJWK, &key.ExchangeFingerprint,
			&key.ExchangeBinding, &key.SigningPublicJWK, &key.SigningFingerprint, &key.DeviceLabel, &createdMS)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			return nil, "", err
		}
		result, err := tx.ExecContext(ctx, `
UPDATE user_prekeys SET claimed_by_user_id = ?, claim_token = ?, claim_token_hash = ?, claim_expires_at = ?
WHERE id = ? AND used_at IS NULL AND (claim_expires_at IS NULL OR claim_expires_at <= ?)`,
			senderID, claimToken, tokenHash, expiresMS, key.ID, now.UTC().UnixMilli())
		if err != nil {
			return nil, "", err
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			continue
		}
		key.CreatedAt = time.UnixMilli(createdMS).UTC()
		claimed = append(claimed, key)
	}
	if len(claimed) == 0 {
		return nil, "", sql.ErrNoRows
	}
	if err := tx.Commit(); err != nil {
		return nil, "", err
	}
	return claimed, claimToken, nil
}

func claimedPrekeys(ctx context.Context, tx *sql.Tx, recipientID, senderID, claimToken string, now time.Time) ([]OneTimePrekey, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT p.id, p.user_id, p.exchange_key_id, p.signing_key_id, p.public_jwk, p.fingerprint,
       p.binding_version, p.binding_signature, x.public_jwk, x.fingerprint, x.binding_signature,
       k.public_jwk, k.fingerprint, x.device_label, p.created_at
FROM user_prekeys p
JOIN user_exchange_keys x ON x.id = p.exchange_key_id AND x.user_id = p.user_id AND x.revoked_at IS NULL
JOIN user_keys k ON k.id = p.signing_key_id AND k.user_id = p.user_id AND k.revoked_at IS NULL
WHERE p.user_id = ? AND p.claimed_by_user_id = ? AND p.claim_token = ?
  AND p.used_at IS NULL AND p.claim_expires_at > ?
ORDER BY x.created_at`, recipientID, senderID, claimToken, now.UTC().UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := make([]OneTimePrekey, 0, 4)
	for rows.Next() {
		var key OneTimePrekey
		var createdMS int64
		if err := rows.Scan(&key.ID, &key.UserID, &key.ExchangeKeyID, &key.SigningKeyID, &key.PublicJWK, &key.Fingerprint,
			&key.BindingVersion, &key.BindingSignature, &key.ExchangePublicJWK, &key.ExchangeFingerprint,
			&key.ExchangeBinding, &key.SigningPublicJWK, &key.SigningFingerprint, &key.DeviceLabel, &createdMS); err != nil {
			return nil, err
		}
		key.CreatedAt = time.UnixMilli(createdMS).UTC()
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (s *Store) Devices(ctx context.Context, userID string) ([]Device, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT x.id, x.signing_key_id, x.device_label, x.fingerprint, k.fingerprint,
       x.created_at, x.last_seen_at, x.revoked_at
FROM user_exchange_keys x
JOIN user_keys k ON k.id = x.signing_key_id AND k.user_id = x.user_id
WHERE x.user_id = ? ORDER BY x.revoked_at IS NOT NULL, x.last_seen_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	devices := make([]Device, 0, 4)
	for rows.Next() {
		var device Device
		var createdMS, lastSeenMS int64
		var revokedMS sql.NullInt64
		if err := rows.Scan(&device.ExchangeKeyID, &device.SigningKeyID, &device.DeviceLabel,
			&device.ExchangeFingerprint, &device.SigningFingerprint, &createdMS, &lastSeenMS, &revokedMS); err != nil {
			return nil, err
		}
		device.CreatedAt = time.UnixMilli(createdMS).UTC()
		device.LastSeenAt = time.UnixMilli(lastSeenMS).UTC()
		device.RevokedAt = nullTime(revokedMS)
		devices = append(devices, device)
	}
	return devices, rows.Err()
}

func (s *Store) RevokeDevice(ctx context.Context, userID, exchangeKeyID string, now time.Time) error {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var signingKeyID string
	if err := tx.QueryRowContext(ctx, `SELECT signing_key_id FROM user_exchange_keys WHERE id = ? AND user_id = ?`, exchangeKeyID, userID).Scan(&signingKeyID); err != nil {
		return err
	}
	nowMS := now.UTC().UnixMilli()
	if _, err := tx.ExecContext(ctx, `UPDATE user_exchange_keys SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL`, nowMS, exchangeKeyID, userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_keys SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL`, nowMS, signingKeyID, userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_prekeys WHERE exchange_key_id = ? AND used_at IS NULL`, exchangeKeyID); err != nil {
		return err
	}
	return tx.Commit()
}

func hashClaimToken(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
