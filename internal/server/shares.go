package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"database/sql"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/LaplaceOrange/fly/internal/store"
	"github.com/go-chi/chi/v5"
)

type publicJWK struct {
	Kty    string   `json:"kty"`
	Crv    string   `json:"crv"`
	X      string   `json:"x"`
	Y      string   `json:"y"`
	Ext    bool     `json:"ext,omitempty"`
	KeyOps []string `json:"key_ops,omitempty"`
}

type shareRequest struct {
	Encrypted bool   `json:"encrypted"`
	Payload   string `json:"payload"`
	IV        string `json:"iv"`
	Signature string `json:"signature"`
	KeyID     string `json:"keyId"`
}

func (s *Server) registerSigningKey(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication_required", "请先登录后注册签名密钥", 0)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	var request struct {
		PublicJWK publicJWK `json:"publicJwk"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_key", "签名公钥格式无效", 0)
		return
	}
	if _, err := parsePublicKey(request.PublicJWK); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_key", "仅支持 P-256 ECDSA 公钥", 0)
		return
	}
	canonical, _ := json.Marshal(request.PublicJWK)
	fingerprintRaw := sha256.Sum256(canonical)
	fingerprint := base64.RawURLEncoding.EncodeToString(fingerprintRaw[:])
	keyID, err := randomToken(12)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	key, err := s.store.RegisterSigningKey(r.Context(), store.SigningKey{
		ID: keyID, UserID: user.ID, PublicJWK: string(canonical), Fingerprint: fingerprint, CreatedAt: time.Now(),
	})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"keyId": key.ID, "fingerprint": key.Fingerprint})
}

func (s *Server) createShare(w http.ResponseWriter, r *http.Request) {
	user, ok := s.currentUser(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication_required", "请先登录后创建分享", 0)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
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
	if request.Encrypted {
		iv, err := base64.RawURLEncoding.DecodeString(request.IV)
		if err != nil || len(iv) != 12 {
			writeError(w, http.StatusBadRequest, "invalid_share_iv", "AES-GCM IV 必须为 12 字节", 0)
			return
		}
		if _, err := base64.RawURLEncoding.DecodeString(request.Payload); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_ciphertext", "加密分享密文无效", 0)
			return
		}
	} else if request.IV != "" || !json.Valid([]byte(request.Payload)) {
		writeError(w, http.StatusBadRequest, "invalid_plain_share", "普通分享必须包含有效 JSON 且不能携带 IV", 0)
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
	var jwk publicJWK
	if err := json.Unmarshal([]byte(key.PublicJWK), &jwk); err != nil {
		s.internalError(w, r, err)
		return
	}
	publicKey, err := parsePublicKey(jwk)
	if err != nil || !verifyShareSignature(publicKey, request) {
		writeError(w, http.StatusBadRequest, "signature_invalid", "分享签名验证失败", 0)
		return
	}
	shareID, err := randomToken(12)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	now := time.Now().UTC()
	expires := now.Add(s.cfg.ShareTTL)
	if err := s.store.CreateShare(r.Context(), store.Share{
		ID: shareID, Encrypted: request.Encrypted, Payload: request.Payload, IV: request.IV,
		Signature: request.Signature, KeyID: request.KeyID, CreatedAt: now, ExpiresAt: expires,
	}, user.ID); err != nil {
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
	var jwk any
	_ = json.Unmarshal([]byte(share.PublicJWK), &jwk)
	writeJSON(w, http.StatusOK, map[string]any{
		"id": share.ID, "encrypted": share.Encrypted, "payload": share.Payload, "iv": share.IV,
		"signature": share.Signature, "createdAt": share.CreatedAt, "expiresAt": share.ExpiresAt,
		"signer": share.Signer, "keyId": share.KeyID, "publicJwk": jwk, "fingerprint": share.Fingerprint,
	})
}

func parsePublicKey(jwk publicJWK) (*ecdsa.PublicKey, error) {
	if jwk.Kty != "EC" || jwk.Crv != "P-256" {
		return nil, errors.New("unsupported key")
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, err
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, err
	}
	x, y := new(big.Int).SetBytes(xBytes), new(big.Int).SetBytes(yBytes)
	curve := elliptic.P256()
	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("point is not on P-256")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func verifyShareSignature(publicKey *ecdsa.PublicKey, request shareRequest) bool {
	signature, err := base64.RawURLEncoding.DecodeString(request.Signature)
	if err != nil {
		return false
	}
	digest := sha256.Sum256([]byte(shareSigningInput(request.Encrypted, request.Payload, request.IV)))
	if len(signature) == 64 {
		r := new(big.Int).SetBytes(signature[:32])
		s := new(big.Int).SetBytes(signature[32:])
		return ecdsa.Verify(publicKey, digest[:], r, s)
	}
	var parsed struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(signature, &parsed); err != nil || parsed.R == nil || parsed.S == nil {
		return false
	}
	return ecdsa.Verify(publicKey, digest[:], parsed.R, parsed.S)
}

func shareSigningInput(encrypted bool, payload, iv string) string {
	flag := "0"
	if encrypted {
		flag = "1"
	}
	return strings.Join([]string{"share-sign-v1", flag, payload, iv}, "\n")
}
