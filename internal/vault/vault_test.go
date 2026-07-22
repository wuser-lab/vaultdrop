package vault

import (
	"bytes"
	"testing"
)

func TestRoundTripAndTamperDetection(t *testing.T) {
	privateKey, publicKey, err := GenerateKeyPair(2048)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("confidential document")
	envelope, err := Encrypt(publicKey, message, []byte("contract.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := Decrypt(privateKey, envelope, []byte("contract.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, message) {
		t.Fatalf("got %q", plain)
	}
	if _, err := Decrypt(privateKey, envelope, []byte("renamed.pdf")); err == nil {
		t.Fatal("tampered metadata was accepted")
	}
}

func TestRejectsWeakKeys(t *testing.T) {
	if _, _, err := GenerateKeyPair(1024); err == nil {
		t.Fatal("expected weak key rejection")
	}
}
