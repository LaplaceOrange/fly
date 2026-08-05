package server

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/LaplaceOrange/fly/internal/store"
	"github.com/go-chi/chi/v5"
)

const (
	ed25519Algorithm     = "Ed25519"
	publicCryptoSuite    = "Ed25519"
	encryptedCryptoSuite = "X25519-OTPK-HKDF-SHA256-AES-256-GCM+Ed25519"
	exchangeBindingV1    = 1
	prekeyBindingV1      = 1
	shareSignatureV3     = 3
)

type okpPublicJWK struct {
	Kty    string   `json:"kty"`
	Crv    string   `json:"crv"`
	X      string   `json:"x"`
	Ext    bool     `json:"ext,omitempty"`
	KeyOps []string `json:"key_ops,omitempty"`
}

type keyEnvelope struct {
	KeyID      string `json:"keyId"`
	Salt       string `json:"salt"`
	IV         string `json:"iv"`
	WrappedKey string `json:"wrappedKey"`
}

type shareRequest struct {
	Encrypted          bool          `json:"encrypted"`
	Payload            string        `json:"payload"`
	IV                 string        `json:"iv"`
	Signature          string        `json:"signature"`
	KeyID              string        `json:"keyId"`
	SenderUserID       string        `json:"senderUserId,omitempty"`
	SignatureVersion   int           `json:"signatureVersion,omitempty"`
	CryptoSuite        string        `json:"cryptoSuite,omitempty"`
	RecipientUserID    string        `json:"recipientUserId,omitempty"`
	EphemeralPublicJWK okpPublicJWK  `json:"ephemeralPublicJwk,omitempty"`
	KeyEnvelopes       []keyEnvelope `json:"keyEnvelopes,omitempty"`
	ExpiresAt          string        `json:"expiresAt,omitempty"`
	PrekeyClaimToken   string        `json:"prekeyClaimToken,omitempty"`
}

type prekeyRequest struct {
	PublicJWK        okpPublicJWK `json:"publicJwk"`
	ExchangeKeyID    string       `json:"exchangeKeyId"`
	SigningKeyID     string       `json:"signingKeyId"`
	BindingVersion   int          `json:"bindingVersion"`
	BindingSignature string       `json:"bindingSignature"`
}

func (s *Server) registerSigningKey(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication_required", "请先登录后注册签名密钥", 0)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	var request struct {
		PublicJWK   okpPublicJWK `json:"publicJwk"`
		DeviceLabel string       `json:"deviceLabel"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_key", "签名公钥格式无效", 0)
		return
	}
	publicKey, err := parseOKPPublicKey(request.PublicJWK, "Ed25519")
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		writeError(w, http.StatusBadRequest, "invalid_key", "仅支持 Ed25519 签名公钥", 0)
		return
	}
	canonical, fingerprint := canonicalOKPKey(request.PublicJWK)
	keyID, err := randomToken(12)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	now := time.Now().UTC()
	key, err := s.store.RegisterSigningKey(r.Context(), store.SigningKey{
		ID: keyID, UserID: user.ID, Algorithm: ed25519Algorithm, PublicJWK: canonical,
		Fingerprint: fingerprint, DeviceLabel: cleanDeviceLabel(request.DeviceLabel), CreatedAt: now, LastSeenAt: now,
	})
	if err != nil {
		if errors.Is(err, store.ErrKeyRevoked) {
			writeError(w, http.StatusConflict, "key_revoked", "该设备签名密钥已撤销，请在本设备生成新密钥", 0)
			return
		}
		if errors.Is(err, store.ErrDeviceKeyLimit) {
			writeError(w, http.StatusConflict, "device_key_limit", "该账号注册的设备签名密钥已达到上限", 0)
			return
		}
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"keyId": key.ID, "fingerprint": key.Fingerprint, "algorithm": key.Algorithm})
}

func (s *Server) registerExchangeKey(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication_required", "请先登录后注册密钥交换公钥", 0)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	var request struct {
		PublicJWK        okpPublicJWK `json:"publicJwk"`
		SigningKeyID     string       `json:"signingKeyId"`
		BindingVersion   int          `json:"bindingVersion"`
		BindingSignature string       `json:"bindingSignature"`
		DeviceLabel      string       `json:"deviceLabel"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_exchange_key", "密钥交换公钥格式无效", 0)
		return
	}
	publicKey, err := parseOKPPublicKey(request.PublicJWK, "X25519")
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_exchange_key", "仅支持 X25519 密钥交换公钥", 0)
		return
	}
	if err := validateX25519PublicKey(publicKey); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_exchange_key", "X25519 公钥无效", 0)
		return
	}
	if request.BindingVersion != exchangeBindingV1 || request.SigningKeyID == "" {
		writeError(w, http.StatusBadRequest, "invalid_exchange_binding", "X25519 公钥必须携带 Ed25519 v1 绑定签名", 0)
		return
	}
	signingKey, err := s.store.SigningKey(r.Context(), user.ID, request.SigningKeyID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusBadRequest, "unknown_signing_key", "绑定签名使用的 Ed25519 公钥不存在", 0)
			return
		}
		s.internalError(w, r, err)
		return
	}
	if signingKey.Algorithm != ed25519Algorithm {
		writeError(w, http.StatusBadRequest, "wrong_binding_algorithm", "X25519 公钥绑定必须使用 Ed25519 签名", 0)
		return
	}
	if signingKey.RevokedAt != nil {
		writeError(w, http.StatusConflict, "key_revoked", "绑定签名使用的 Ed25519 密钥已撤销", 0)
		return
	}
	var signingJWK okpPublicJWK
	if err := json.Unmarshal([]byte(signingKey.PublicJWK), &signingJWK); err != nil {
		s.internalError(w, r, err)
		return
	}
	signingPublicKey, err := parseOKPPublicKey(signingJWK, "Ed25519")
	if err != nil || !verifyExchangeKeyBindingSignature(ed25519.PublicKey(signingPublicKey), user.ID, request.SigningKeyID, request.PublicJWK, request.BindingSignature) {
		writeError(w, http.StatusBadRequest, "exchange_binding_invalid", "X25519 公钥的 Ed25519 绑定签名验证失败", 0)
		return
	}
	canonical, fingerprint := canonicalOKPKey(request.PublicJWK)
	keyID, err := randomToken(12)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	now := time.Now().UTC()
	key, err := s.store.RegisterExchangeKey(r.Context(), store.ExchangeKey{
		ID: keyID, UserID: user.ID, PublicJWK: canonical, Fingerprint: fingerprint,
		SigningKeyID: request.SigningKeyID, BindingVersion: request.BindingVersion,
		BindingSignature: request.BindingSignature, DeviceLabel: cleanDeviceLabel(request.DeviceLabel), CreatedAt: now, LastSeenAt: now,
	})
	if err != nil {
		if errors.Is(err, store.ErrKeyRevoked) {
			writeError(w, http.StatusConflict, "key_revoked", "该设备交换密钥已撤销，请在本设备生成新密钥", 0)
			return
		}
		if errors.Is(err, store.ErrDeviceKeyLimit) {
			writeError(w, http.StatusConflict, "device_key_limit", "该账号注册的密钥交换设备已达到上限", 0)
			return
		}
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"keyId": key.ID, "fingerprint": key.Fingerprint, "algorithm": "X25519"})
}

func (s *Server) registerPrekeys(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication_required", "请先登录后注册一次性预密钥", 0)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var request struct {
		Prekeys []prekeyRequest `json:"prekeys"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || len(request.Prekeys) < 1 || len(request.Prekeys) > 16 {
		writeError(w, http.StatusBadRequest, "invalid_prekeys", "一次只能注册 1 到 16 个一次性预密钥", 0)
		return
	}
	exchangeKeys, err := s.store.ExchangeKeys(r.Context(), user.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	exchanges := make(map[string]store.ExchangeKey, len(exchangeKeys))
	for _, key := range exchangeKeys {
		exchanges[key.ID] = key
	}
	seen := make(map[string]struct{}, len(request.Prekeys))
	result := make([]map[string]any, 0, len(request.Prekeys))
	for _, candidate := range request.Prekeys {
		exchange, exists := exchanges[candidate.ExchangeKeyID]
		if !exists || exchange.SigningKeyID != candidate.SigningKeyID || candidate.BindingVersion != prekeyBindingV1 {
			writeError(w, http.StatusBadRequest, "invalid_prekey_binding", "一次性预密钥未绑定到当前有效设备", 0)
			return
		}
		raw, err := parseOKPPublicKey(candidate.PublicJWK, "X25519")
		if err != nil || validateX25519PublicKey(raw) != nil {
			writeError(w, http.StatusBadRequest, "invalid_prekey", "一次性 X25519 预密钥无效", 0)
			return
		}
		canonical, fingerprint := canonicalOKPKey(candidate.PublicJWK)
		if _, duplicate := seen[fingerprint]; duplicate {
			writeError(w, http.StatusBadRequest, "duplicate_prekey", "一次性预密钥列表包含重复公钥", 0)
			return
		}
		seen[fingerprint] = struct{}{}
		var signingJWK okpPublicJWK
		if err := json.Unmarshal([]byte(exchange.SigningPublicJWK), &signingJWK); err != nil {
			s.internalError(w, r, err)
			return
		}
		signingPublic, err := parseOKPPublicKey(signingJWK, "Ed25519")
		if err != nil || !verifyPrekeyBindingSignature(ed25519.PublicKey(signingPublic), user.ID, candidate, candidate.BindingSignature) {
			writeError(w, http.StatusBadRequest, "prekey_binding_invalid", "一次性预密钥的 Ed25519 绑定签名验证失败", 0)
			return
		}
		keyID, err := randomToken(12)
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		registered, err := s.store.RegisterPrekey(r.Context(), store.OneTimePrekey{
			ID: keyID, UserID: user.ID, ExchangeKeyID: candidate.ExchangeKeyID, SigningKeyID: candidate.SigningKeyID,
			PublicJWK: canonical, Fingerprint: fingerprint, BindingVersion: candidate.BindingVersion,
			BindingSignature: candidate.BindingSignature, CreatedAt: time.Now().UTC(),
		})
		if err != nil {
			if errors.Is(err, store.ErrKeyRevoked) {
				writeError(w, http.StatusConflict, "key_revoked", "一次性预密钥所属设备已撤销", 0)
				return
			}
			if errors.Is(err, store.ErrPrekeyLimit) {
				writeError(w, http.StatusConflict, "prekey_limit", "该账号保留的一次性预密钥已达到上限", 0)
				return
			}
			s.internalError(w, r, err)
			return
		}
		result = append(result, map[string]any{"keyId": registered.ID, "fingerprint": registered.Fingerprint})
	}
	writeJSON(w, http.StatusCreated, map[string]any{"prekeys": result})
}

func (s *Server) prekeyStatus(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication_required", "请先登录后检查一次性预密钥", 0)
		return
	}
	exchangeKeyID := strings.TrimSpace(r.URL.Query().Get("exchangeKeyId"))
	if exchangeKeyID == "" {
		writeError(w, http.StatusBadRequest, "invalid_exchange_key", "缺少设备交换密钥 ID", 0)
		return
	}
	available, retained, err := s.store.PrekeyInventory(r.Context(), user.ID, exchangeKeyID, time.Now().UTC())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"availableFingerprints": available, "retainedFingerprints": retained})
}

func (s *Server) claimRecipientPrekeys(w http.ResponseWriter, r *http.Request) {
	sender, ok := s.currentUser(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication_required", "请先登录后获取接收者一次性预密钥", 0)
		return
	}
	recipientID := strings.TrimSpace(chi.URLParam(r, "userID"))
	if recipientID == "" || recipientID == sender.ID {
		writeError(w, http.StatusBadRequest, "invalid_recipient", "请选择其他用户作为接收者", 0)
		return
	}
	claimToken, err := randomToken(24)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	keys, claimToken, err := s.store.ClaimPrekeys(r.Context(), recipientID, sender.ID, claimToken, time.Now().UTC())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusConflict, "recipient_has_no_prekeys", "接收者当前没有可用的一次性预密钥，请稍后重试", 0)
			return
		}
		s.internalError(w, r, err)
		return
	}
	result := make([]map[string]any, 0, len(keys))
	for _, key := range keys {
		var prekeyJWK, exchangeJWK, signingJWK any
		if json.Unmarshal([]byte(key.PublicJWK), &prekeyJWK) != nil ||
			json.Unmarshal([]byte(key.ExchangePublicJWK), &exchangeJWK) != nil ||
			json.Unmarshal([]byte(key.SigningPublicJWK), &signingJWK) != nil {
			s.internalError(w, r, errors.New("stored prekey JWK is invalid"))
			return
		}
		result = append(result, map[string]any{
			"keyId": key.ID, "publicJwk": prekeyJWK, "fingerprint": key.Fingerprint,
			"exchangeKeyId": key.ExchangeKeyID, "exchangePublicJwk": exchangeJWK,
			"exchangeFingerprint": key.ExchangeFingerprint, "exchangeBindingSignature": key.ExchangeBinding,
			"signingKeyId": key.SigningKeyID, "signingPublicJwk": signingJWK,
			"signingFingerprint": key.SigningFingerprint, "bindingVersion": key.BindingVersion,
			"bindingSignature": key.BindingSignature, "deviceLabel": key.DeviceLabel,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"claimToken": claimToken, "keys": result})
}

func (s *Server) devices(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication_required", "请先登录后管理设备密钥", 0)
		return
	}
	devices, err := s.store.Devices(r.Context(), user.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": devices})
}

func (s *Server) revokeDevice(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication_required", "请先登录后撤销设备密钥", 0)
		return
	}
	keyID := strings.TrimSpace(chi.URLParam(r, "exchangeKeyID"))
	if err := s.store.RevokeDevice(r.Context(), user.ID, keyID, time.Now().UTC()); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "device_not_found", "设备密钥不存在", 0)
			return
		}
		s.internalError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) shareRecipients(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication_required", "请先登录后选择加密分享接收者", 0)
		return
	}
	recipients, err := s.store.ShareRecipients(r.Context(), user.ID, 100)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recipients": recipients})
}

func (s *Server) recipientExchangeKeys(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication_required", "请先登录后获取接收者公钥", 0)
		return
	}
	userID := strings.TrimSpace(chi.URLParam(r, "userID"))
	if userID == "" || userID == user.ID {
		writeError(w, http.StatusBadRequest, "invalid_recipient", "请选择其他用户作为接收者", 0)
		return
	}
	keys, err := s.store.ExchangeKeys(r.Context(), userID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if len(keys) == 0 {
		writeError(w, http.StatusConflict, "recipient_has_no_keys", "接收者尚未注册可用的 X25519 设备密钥", 0)
		return
	}
	result := make([]map[string]any, 0, len(keys))
	for _, key := range keys {
		var exchangeJWK, signingJWK any
		if err := json.Unmarshal([]byte(key.PublicJWK), &exchangeJWK); err != nil {
			s.internalError(w, r, err)
			return
		}
		if err := json.Unmarshal([]byte(key.SigningPublicJWK), &signingJWK); err != nil {
			s.internalError(w, r, err)
			return
		}
		result = append(result, map[string]any{
			"keyId": key.ID, "publicJwk": exchangeJWK, "fingerprint": key.Fingerprint,
			"signingKeyId": key.SigningKeyID, "bindingVersion": key.BindingVersion,
			"bindingSignature": key.BindingSignature, "signingPublicJwk": signingJWK,
			"signingFingerprint": key.SigningFingerprint,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": result})
}

func (s *Server) createShare(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication_required", "请先登录后创建分享", 0)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 96<<10)
	var request shareRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_share", "分享内容无效", 0)
		return
	}
	if request.KeyID == "" || request.Signature == "" || request.Payload == "" || len(request.Payload) > 48<<10 {
		writeError(w, http.StatusBadRequest, "invalid_share", "分享内容或签名无效", 0)
		return
	}
	if request.SignatureVersion != shareSignatureV3 || request.SenderUserID != user.ID {
		writeError(w, http.StatusBadRequest, "unsupported_signature_version", "新分享必须使用绑定发送者身份的 Ed25519 v3 签名格式", 0)
		return
	}
	expires, err := time.Parse(time.RFC3339Nano, request.ExpiresAt)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_expiry", "分享过期时间格式无效", 0)
		return
	}
	now := time.Now().UTC()
	if expires.Before(now.Add(-5*time.Minute)) || expires.After(now.Add(s.cfg.ShareTTL+5*time.Minute)) {
		writeError(w, http.StatusBadRequest, "invalid_expiry", "分享过期时间超出允许范围", 0)
		return
	}
	if err := s.validateModernShare(r, user, request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_crypto_envelope", err.Error(), 0)
		return
	}
	key, err := s.store.SigningKey(r.Context(), user.ID, request.KeyID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusBadRequest, "unknown_signing_key", "签名密钥未注册", 0)
			return
		}
		s.internalError(w, r, err)
		return
	}
	if key.Algorithm != ed25519Algorithm {
		writeError(w, http.StatusBadRequest, "wrong_signing_algorithm", "新版分享必须使用 Ed25519 签名", 0)
		return
	}
	if key.RevokedAt != nil {
		writeError(w, http.StatusConflict, "key_revoked", "签名设备密钥已撤销", 0)
		return
	}
	var jwk okpPublicJWK
	if err := json.Unmarshal([]byte(key.PublicJWK), &jwk); err != nil {
		s.internalError(w, r, err)
		return
	}
	publicKey, err := parseOKPPublicKey(jwk, "Ed25519")
	if err != nil || !verifyModernShareSignature(ed25519.PublicKey(publicKey), request) {
		writeError(w, http.StatusBadRequest, "signature_invalid", "Ed25519 分享签名验证失败", 0)
		return
	}
	ephemeralJSON := []byte{}
	if request.Encrypted {
		ephemeralJSON, _ = json.Marshal(request.EphemeralPublicJWK)
	}
	envelopesJSON, _ := json.Marshal(request.KeyEnvelopes)
	s.persistShare(w, r, user.ID, request, string(ephemeralJSON), string(envelopesJSON), expires.UTC())
}

func (s *Server) validateModernShare(r *http.Request, user store.User, request shareRequest) error {
	if request.Encrypted {
		if request.CryptoSuite != encryptedCryptoSuite {
			return errors.New("加密分享必须使用 X25519 一次性预密钥/HKDF-SHA-256/AES-256-GCM/Ed25519 套件")
		}
		if request.RecipientUserID == "" || request.RecipientUserID == user.ID {
			return errors.New("端到端加密分享必须指定其他接收用户")
		}
		if decoded, err := base64.RawURLEncoding.DecodeString(request.Payload); err != nil || len(decoded) < 16 {
			return errors.New("AES-GCM 密文无效")
		}
		if !encodedLength(request.IV, 12) {
			return errors.New("AES-GCM IV 必须为 12 字节")
		}
		ephemeral, err := parseOKPPublicKey(request.EphemeralPublicJWK, "X25519")
		if err != nil {
			return errors.New("临时 X25519 公钥无效")
		}
		if err := validateX25519PublicKey(ephemeral); err != nil {
			return errors.New("临时 X25519 公钥无效")
		}
		if len(request.KeyEnvelopes) < 1 || len(request.KeyEnvelopes) > 32 {
			return errors.New("接收者密钥信封数量无效")
		}
		if len(request.PrekeyClaimToken) < 20 || len(request.PrekeyClaimToken) > 128 {
			return errors.New("一次性预密钥领取凭据无效")
		}
		seen := make(map[string]struct{}, len(request.KeyEnvelopes))
		for _, envelope := range request.KeyEnvelopes {
			if envelope.KeyID == "" || len(envelope.KeyID) > 64 {
				return errors.New("密钥信封引用的一次性预密钥 ID 无效")
			}
			if _, duplicate := seen[envelope.KeyID]; duplicate {
				return errors.New("密钥信封包含重复设备密钥")
			}
			seen[envelope.KeyID] = struct{}{}
			if !encodedLength(envelope.Salt, 16) || !encodedLength(envelope.IV, 12) || !encodedLength(envelope.WrappedKey, 48) {
				return errors.New("密钥包装参数长度无效")
			}
		}
		return nil
	}
	if request.CryptoSuite != publicCryptoSuite || request.RecipientUserID != "" || request.EphemeralPublicJWK.X != "" || len(request.KeyEnvelopes) != 0 || request.PrekeyClaimToken != "" {
		return errors.New("公开分享必须使用 Ed25519 且不能携带密钥交换数据")
	}
	if request.IV != "" || validatePublicSharePayload(request.Payload, user.ID) != nil {
		return errors.New("公开分享必须包含有效 JSON 且不能携带 IV")
	}
	return nil
}

func (s *Server) persistShare(w http.ResponseWriter, r *http.Request, userID string, request shareRequest, ephemeralJSON, envelopesJSON string, expires time.Time) {
	shareID, err := randomToken(12)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	now := time.Now().UTC()
	prekeyIDs := make([]string, 0, len(request.KeyEnvelopes))
	for _, envelope := range request.KeyEnvelopes {
		prekeyIDs = append(prekeyIDs, envelope.KeyID)
	}
	if err := s.store.CreateShare(r.Context(), store.Share{
		ID: shareID, Encrypted: request.Encrypted, Payload: request.Payload, IV: request.IV,
		Signature: request.Signature, SignatureVersion: request.SignatureVersion, CryptoSuite: request.CryptoSuite,
		RecipientUserID: request.RecipientUserID, EphemeralPublicJWK: ephemeralJSON, KeyEnvelopes: envelopesJSON,
		KeyID: request.KeyID, SignedExpiresAt: request.ExpiresAt, CreatedAt: now, ExpiresAt: expires,
	}, userID, request.PrekeyClaimToken, prekeyIDs); err != nil {
		if errors.Is(err, store.ErrPrekeyClaim) {
			writeError(w, http.StatusConflict, "prekey_claim_expired", "一次性预密钥领取已过期，请重新选择接收者", 0)
			return
		}
		s.internalError(w, r, err)
		return
	}
	shareURL := s.cfg.PublicBaseURL.ResolveReference(&url.URL{Path: "/share/" + shareID}).String()
	writeJSON(w, http.StatusCreated, map[string]any{"id": shareID, "url": shareURL, "expiresAt": expires})
}

func (s *Server) getShare(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "shareID")
	if len(id) < 12 || len(id) > 64 {
		writeError(w, http.StatusNotFound, "share_not_found", "分享不存在或已过期", 0)
		return
	}
	share, err := s.store.Share(r.Context(), id, time.Now())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "share_not_found", "分享不存在或已过期", 0)
			return
		}
		s.internalError(w, r, err)
		return
	}
	if share.Encrypted && share.SignatureVersion >= 2 {
		viewer, ok := s.currentUser(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "authentication_required", "请登录接收者账号后解密此分享", 0)
			return
		}
		if viewer.ID != share.RecipientUserID {
			writeError(w, http.StatusForbidden, "not_share_recipient", "此端到端加密分享不是发送给当前用户的", 0)
			return
		}
	}
	var signingJWK any
	if err := json.Unmarshal([]byte(share.PublicJWK), &signingJWK); err != nil {
		s.internalError(w, r, err)
		return
	}
	var ephemeralJWK any
	if share.EphemeralPublicJWK != "" {
		if err := json.Unmarshal([]byte(share.EphemeralPublicJWK), &ephemeralJWK); err != nil {
			s.internalError(w, r, err)
			return
		}
	}
	var envelopes any = []any{}
	if share.KeyEnvelopes != "" {
		if err := json.Unmarshal([]byte(share.KeyEnvelopes), &envelopes); err != nil {
			s.internalError(w, r, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": share.ID, "encrypted": share.Encrypted, "payload": share.Payload, "iv": share.IV,
		"signature": share.Signature, "signatureVersion": share.SignatureVersion, "cryptoSuite": share.CryptoSuite,
		"recipientUserId": share.RecipientUserID, "ephemeralPublicJwk": ephemeralJWK, "keyEnvelopes": envelopes,
		"createdAt": share.CreatedAt, "expiresAt": share.SignedExpiresAt, "signer": share.Signer,
		"keyId": share.KeyID, "signingAlgorithm": share.SigningAlgorithm, "publicJwk": signingJWK, "fingerprint": share.Fingerprint,
	})
}

func canonicalOKPKey(jwk okpPublicJWK) (string, string) {
	canonical, _ := json.Marshal(struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
	}{Kty: jwk.Kty, Crv: jwk.Crv, X: jwk.X})
	fingerprintRaw := sha256.Sum256(canonical)
	return string(canonical), base64.RawURLEncoding.EncodeToString(fingerprintRaw[:])
}

func parseOKPPublicKey(jwk okpPublicJWK, curve string) ([]byte, error) {
	if jwk.Kty != "OKP" || jwk.Crv != curve {
		return nil, errors.New("unsupported OKP key")
	}
	key, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil || len(key) != 32 {
		return nil, errors.New("invalid OKP key")
	}
	return key, nil
}

func validateX25519PublicKey(raw []byte) error {
	publicKey, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return err
	}
	validationScalar := make([]byte, 32)
	validationScalar[0] = 1
	privateKey, err := ecdh.X25519().NewPrivateKey(validationScalar)
	if err != nil {
		return err
	}
	_, err = privateKey.ECDH(publicKey)
	return err
}

func verifyModernShareSignature(publicKey ed25519.PublicKey, request shareRequest) bool {
	signature, err := base64.RawURLEncoding.DecodeString(request.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(publicKey, []byte(modernShareSigningInput(request)), signature)
}

func verifyExchangeKeyBindingSignature(publicKey ed25519.PublicKey, userID, signingKeyID string, exchangeJWK okpPublicJWK, signatureValue string) bool {
	signature, err := base64.RawURLEncoding.DecodeString(signatureValue)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(publicKey, []byte(exchangeKeyBindingInput(userID, signingKeyID, exchangeJWK)), signature)
}

func verifyPrekeyBindingSignature(publicKey ed25519.PublicKey, userID string, request prekeyRequest, signatureValue string) bool {
	signature, err := base64.RawURLEncoding.DecodeString(signatureValue)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(publicKey, []byte(prekeyBindingInput(userID, request.SigningKeyID, request.ExchangeKeyID, request.PublicJWK)), signature)
}

func exchangeKeyBindingInput(userID, signingKeyID string, exchangeJWK okpPublicJWK) string {
	return lengthPrefixedInput("exchange-key-binding-v1", []string{userID, signingKeyID, ed25519Algorithm, "X25519", exchangeJWK.X})
}

func prekeyBindingInput(userID, signingKeyID, exchangeKeyID string, prekeyJWK okpPublicJWK) string {
	return lengthPrefixedInput("prekey-binding-v1", []string{userID, signingKeyID, exchangeKeyID, ed25519Algorithm, "X25519", prekeyJWK.X})
}

func modernShareSigningInput(request shareRequest) string {
	envelopes := append([]keyEnvelope(nil), request.KeyEnvelopes...)
	sort.Slice(envelopes, func(i, j int) bool { return envelopes[i].KeyID < envelopes[j].KeyID })
	fields := []string{
		strconv.Itoa(request.SignatureVersion),
		request.SenderUserID,
		request.CryptoSuite,
		strconv.FormatBool(request.Encrypted),
		request.Payload,
		request.IV,
		request.RecipientUserID,
		request.EphemeralPublicJWK.X,
		request.ExpiresAt,
		strconv.Itoa(len(envelopes)),
	}
	for _, envelope := range envelopes {
		fields = append(fields, envelope.KeyID, envelope.Salt, envelope.IV, envelope.WrappedKey)
	}
	return lengthPrefixedInput("share-sign-v3", fields)
}

func validatePublicSharePayload(raw, userID string) error {
	var payload struct {
		Version  int    `json:"version"`
		SharedAt string `json:"sharedAt"`
		Message  string `json:"message"`
		User     struct {
			ID           string  `json:"id"`
			Username     string  `json:"username"`
			DisplayName  string  `json:"displayName"`
			AvatarURL    string  `json:"avatarUrl"`
			TotalFlights float64 `json:"totalFlights"`
			LastFlightAt any     `json:"lastFlightAt"`
		} `json:"user"`
		Snapshot struct {
			TotalFlights float64 `json:"totalFlights"`
			TotalUsers   float64 `json:"totalUsers"`
			RangeFlights float64 `json:"rangeFlights"`
			Range        string  `json:"range"`
		} `json:"snapshot"`
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return err
	}
	if payload.Version != 1 || payload.User.ID != userID || strings.TrimSpace(payload.Message) == "" || len([]rune(payload.Message)) > 280 {
		return errors.New("invalid share payload")
	}
	if _, err := time.Parse(time.RFC3339Nano, payload.SharedAt); err != nil {
		return err
	}
	if payload.User.Username == "" || payload.User.DisplayName == "" || !validShareCount(payload.User.TotalFlights) ||
		!validShareCount(payload.Snapshot.TotalFlights) || !validShareCount(payload.Snapshot.TotalUsers) || !validShareCount(payload.Snapshot.RangeFlights) {
		return errors.New("invalid share statistics")
	}
	switch payload.Snapshot.Range {
	case "24h", "7d", "1month", "all":
		return nil
	default:
		return errors.New("invalid share range")
	}
}

func validShareCount(value float64) bool {
	return value >= 0 && value <= float64(1<<53-1) && math.Trunc(value) == value
}

func cleanDeviceLabel(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "浏览器设备"
	}
	runes := []rune(value)
	if len(runes) > 80 {
		runes = runes[:80]
	}
	return string(runes)
}

func lengthPrefixedInput(header string, fields []string) string {
	var builder strings.Builder
	builder.WriteString(header)
	builder.WriteByte('\n')
	for _, field := range fields {
		builder.WriteString(strconv.Itoa(len(field)))
		builder.WriteByte(':')
		builder.WriteString(field)
		builder.WriteByte('\n')
	}
	return builder.String()
}

func encodedLength(value string, expected int) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == expected
}
