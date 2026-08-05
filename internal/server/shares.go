package server

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	encryptedCryptoSuite = "X25519-HKDF-SHA256-AES-256-GCM+Ed25519"
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
	SignatureVersion   int           `json:"signatureVersion,omitempty"`
	CryptoSuite        string        `json:"cryptoSuite,omitempty"`
	RecipientUserID    string        `json:"recipientUserId,omitempty"`
	EphemeralPublicJWK okpPublicJWK  `json:"ephemeralPublicJwk,omitempty"`
	KeyEnvelopes       []keyEnvelope `json:"keyEnvelopes,omitempty"`
}

func (s *Server) registerSigningKey(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication_required", "请先登录后注册签名密钥", 0)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	var request struct {
		PublicJWK okpPublicJWK `json:"publicJwk"`
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
	key, err := s.store.RegisterSigningKey(r.Context(), store.SigningKey{
		ID: keyID, UserID: user.ID, Algorithm: ed25519Algorithm, PublicJWK: canonical,
		Fingerprint: fingerprint, CreatedAt: time.Now(),
	})
	if err != nil {
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
		PublicJWK okpPublicJWK `json:"publicJwk"`
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
	canonical, fingerprint := canonicalOKPKey(request.PublicJWK)
	keyID, err := randomToken(12)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	key, err := s.store.RegisterExchangeKey(r.Context(), store.ExchangeKey{
		ID: keyID, UserID: user.ID, PublicJWK: canonical, Fingerprint: fingerprint, CreatedAt: time.Now(),
	})
	if err != nil {
		if errors.Is(err, store.ErrDeviceKeyLimit) {
			writeError(w, http.StatusConflict, "device_key_limit", "该账号注册的密钥交换设备已达到上限", 0)
			return
		}
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"keyId": key.ID, "fingerprint": key.Fingerprint, "algorithm": "X25519"})
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
		var jwk any
		if err := json.Unmarshal([]byte(key.PublicJWK), &jwk); err != nil {
			s.internalError(w, r, err)
			return
		}
		result = append(result, map[string]any{"keyId": key.ID, "publicJwk": jwk, "fingerprint": key.Fingerprint})
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
	if request.SignatureVersion != 2 {
		writeError(w, http.StatusBadRequest, "unsupported_signature_version", "新分享必须使用 Ed25519 v2 签名格式", 0)
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
	s.persistShare(w, r, user.ID, request, string(ephemeralJSON), string(envelopesJSON))
}

func (s *Server) validateModernShare(r *http.Request, user store.User, request shareRequest) error {
	if request.Encrypted {
		if request.CryptoSuite != encryptedCryptoSuite {
			return errors.New("加密分享必须使用 X25519/HKDF-SHA-256/AES-256-GCM/Ed25519 套件")
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
		keys, err := s.store.ExchangeKeys(r.Context(), request.RecipientUserID)
		if err != nil {
			return errors.New("无法读取接收者公钥")
		}
		registered := make(map[string]struct{}, len(keys))
		for _, key := range keys {
			registered[key.ID] = struct{}{}
		}
		seen := make(map[string]struct{}, len(request.KeyEnvelopes))
		for _, envelope := range request.KeyEnvelopes {
			if _, ok := registered[envelope.KeyID]; !ok {
				return errors.New("密钥信封引用了不属于接收者的设备密钥")
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
	if request.CryptoSuite != publicCryptoSuite || request.RecipientUserID != "" || request.EphemeralPublicJWK.X != "" || len(request.KeyEnvelopes) != 0 {
		return errors.New("公开分享必须使用 Ed25519 且不能携带密钥交换数据")
	}
	if request.IV != "" || !json.Valid([]byte(request.Payload)) {
		return errors.New("公开分享必须包含有效 JSON 且不能携带 IV")
	}
	return nil
}

func (s *Server) persistShare(w http.ResponseWriter, r *http.Request, userID string, request shareRequest, ephemeralJSON, envelopesJSON string) {
	shareID, err := randomToken(12)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	now := time.Now().UTC()
	expires := now.Add(s.cfg.ShareTTL)
	if err := s.store.CreateShare(r.Context(), store.Share{
		ID: shareID, Encrypted: request.Encrypted, Payload: request.Payload, IV: request.IV,
		Signature: request.Signature, SignatureVersion: request.SignatureVersion, CryptoSuite: request.CryptoSuite,
		RecipientUserID: request.RecipientUserID, EphemeralPublicJWK: ephemeralJSON, KeyEnvelopes: envelopesJSON,
		KeyID: request.KeyID, CreatedAt: now, ExpiresAt: expires,
	}, userID); err != nil {
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
		"createdAt": share.CreatedAt, "expiresAt": share.ExpiresAt, "signer": share.Signer,
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

func modernShareSigningInput(request shareRequest) string {
	envelopes := append([]keyEnvelope(nil), request.KeyEnvelopes...)
	sort.Slice(envelopes, func(i, j int) bool { return envelopes[i].KeyID < envelopes[j].KeyID })
	fields := []string{
		request.CryptoSuite,
		strconv.FormatBool(request.Encrypted),
		request.Payload,
		request.IV,
		request.RecipientUserID,
		request.EphemeralPublicJWK.X,
		strconv.Itoa(len(envelopes)),
	}
	for _, envelope := range envelopes {
		fields = append(fields, envelope.KeyID, envelope.Salt, envelope.IV, envelope.WrappedKey)
	}
	var builder strings.Builder
	builder.WriteString("share-sign-v2\n")
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
