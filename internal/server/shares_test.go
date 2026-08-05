package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestVerifyModernShareSignature(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := shareRequest{
		Encrypted: false, Payload: `{"version":1}`, SenderUserID: "sender", SignatureVersion: 3, CryptoSuite: publicCryptoSuite,
		ExpiresAt: "2026-01-01T00:00:00Z",
	}
	request.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(modernShareSigningInput(request))))
	if !verifyModernShareSignature(publicKey, request) {
		t.Fatal("valid Ed25519 share signature was rejected")
	}
	request.Payload = `{"version":2}`
	if verifyModernShareSignature(publicKey, request) {
		t.Fatal("modified modern share payload was accepted")
	}
}

func TestModernShareSigningInputCanonicalFormat(t *testing.T) {
	t.Parallel()
	request := shareRequest{Encrypted: false, Payload: `起飞`, SenderUserID: "sender", SignatureVersion: 3, CryptoSuite: publicCryptoSuite, ExpiresAt: "2026-01-01T00:00:00Z"}
	want := "share-sign-v3\n1:3\n6:sender\n7:Ed25519\n5:false\n6:起飞\n0:\n0:\n0:\n20:2026-01-01T00:00:00Z\n1:0\n"
	if got := modernShareSigningInput(request); got != want {
		t.Fatalf("canonical input mismatch\nwant: %q\n got: %q", want, got)
	}
}

func TestExchangeKeyBindingSignatureAndCanonicalFormat(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	exchangeJWK := okpPublicJWK{Kty: "OKP", Crv: "X25519", X: "x"}
	_, fingerprint := canonicalOKPKey(exchangeJWK)
	if fingerprint != "WrTGFJjPeIHHytZ5ehJyyCmZdmf6dEMtnhnHFKhqMYU" {
		t.Fatalf("unexpected X25519 fingerprint: %s", fingerprint)
	}
	input := exchangeKeyBindingInput("用户", "sig", exchangeJWK)
	want := "exchange-key-binding-v1\n6:用户\n3:sig\n7:Ed25519\n6:X25519\n1:x\n"
	if input != want {
		t.Fatalf("binding canonical input mismatch\nwant: %q\n got: %q", want, input)
	}
	signature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(input)))
	if !verifyExchangeKeyBindingSignature(publicKey, "用户", "sig", exchangeJWK, signature) {
		t.Fatal("valid X25519 Ed25519 binding was rejected")
	}
	exchangeJWK.X = "changed"
	if verifyExchangeKeyBindingSignature(publicKey, "用户", "sig", exchangeJWK, signature) {
		t.Fatal("modified X25519 public key binding was accepted")
	}
}

func TestValidateX25519PublicKeyRejectsLowOrderPoint(t *testing.T) {
	t.Parallel()
	if err := validateX25519PublicKey(make([]byte, 32)); err == nil {
		t.Fatal("all-zero X25519 public key was accepted")
	}
}
