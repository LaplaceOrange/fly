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
		Encrypted: false, Payload: `{"version":1}`, SignatureVersion: 2, CryptoSuite: publicCryptoSuite,
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
	request := shareRequest{Encrypted: false, Payload: `起飞`, SignatureVersion: 2, CryptoSuite: publicCryptoSuite}
	want := "share-sign-v2\n7:Ed25519\n5:false\n6:起飞\n0:\n0:\n0:\n1:0\n"
	if got := modernShareSigningInput(request); got != want {
		t.Fatalf("canonical input mismatch\nwant: %q\n got: %q", want, got)
	}
}

func TestValidateX25519PublicKeyRejectsLowOrderPoint(t *testing.T) {
	t.Parallel()
	if err := validateX25519PublicKey(make([]byte, 32)); err == nil {
		t.Fatal("all-zero X25519 public key was accepted")
	}
}
