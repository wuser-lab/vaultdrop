package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
)

type Envelope struct {
	Version    int    `json:"version"`
	Algorithm  string `json:"algorithm"`
	WrappedKey string `json:"wrapped_key"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func GenerateKeyPair(bits int) ([]byte, []byte, error) {
	if bits < 2048 {
		return nil, nil, errors.New("RSA keys must be at least 2048 bits")
	}
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	privateDER := x509.MarshalPKCS1PrivateKey(key)
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateDER})
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	return privatePEM, publicPEM, nil
}

func parsePublic(data []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid public key PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("key is not RSA")
	}
	return key, nil
}

func parsePrivate(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("invalid private key PEM")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func Encrypt(publicPEM, plaintext, associatedData []byte) ([]byte, error) {
	publicKey, err := parsePublic(publicPEM)
	if err != nil {
		return nil, err
	}
	dataKey := make([]byte, 32)
	if _, err = io.ReadFull(rand.Reader, dataKey); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, associatedData)
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, dataKey, []byte("vaultdrop:v1"))
	if err != nil {
		return nil, err
	}
	e := Envelope{Version: 1, Algorithm: "RSA-OAEP-SHA256+AES-256-GCM", WrappedKey: b64(wrapped), Nonce: b64(nonce), Ciphertext: b64(ciphertext)}
	return json.MarshalIndent(e, "", "  ")
}

func Decrypt(privatePEM, envelopeJSON, associatedData []byte) ([]byte, error) {
	privateKey, err := parsePrivate(privatePEM)
	if err != nil {
		return nil, err
	}
	var e Envelope
	if err = json.Unmarshal(envelopeJSON, &e); err != nil {
		return nil, err
	}
	if e.Version != 1 || e.Algorithm != "RSA-OAEP-SHA256+AES-256-GCM" {
		return nil, errors.New("unsupported envelope")
	}
	wrapped, err := unb64(e.WrappedKey)
	if err != nil {
		return nil, err
	}
	dataKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, wrapped, []byte("vaultdrop:v1"))
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, err := unb64(e.Nonce)
	if err != nil {
		return nil, err
	}
	ciphertext, err := unb64(e.Ciphertext)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, associatedData)
}

func b64(v []byte) string            { return base64.RawURLEncoding.EncodeToString(v) }
func unb64(v string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(v) }
