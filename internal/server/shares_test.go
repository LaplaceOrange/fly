package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"testing"
)

func TestVerifyShareSignature(t *testing.T) {
	t.Parallel()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := shareRequest{Encrypted: true, Payload: "ciphertext", IV: "iv"}
	digest := sha256.Sum256([]byte(shareSigningInput(request.Encrypted, request.Payload, request.IV)))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := append(pad32(r), pad32(s)...)
	request.Signature = base64.RawURLEncoding.EncodeToString(raw)
	if !verifyShareSignature(&privateKey.PublicKey, request) {
		t.Fatal("valid share signature was rejected")
	}
	request.Payload = "modified"
	if verifyShareSignature(&privateKey.PublicKey, request) {
		t.Fatal("modified share payload was accepted")
	}
}

func pad32(value *big.Int) []byte {
	result := make([]byte, 32)
	bytes := value.Bytes()
	copy(result[32-len(bytes):], bytes)
	return result
}
