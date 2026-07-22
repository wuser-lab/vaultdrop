# VaultDrop

VaultDrop is an auditable command-line tool for end-to-end encrypted file exchange. Every file gets a fresh AES-256-GCM data key; the key is wrapped for the recipient with RSA-OAEP-SHA256. Authenticated associated data binds the logical filename to the ciphertext, so renaming or tampering fails closed.

## Security properties

- Hybrid encryption supports files of arbitrary size without using RSA on file contents.
- AEAD provides confidentiality and integrity.
- A unique random key and nonce are generated per envelope.
- Private keys are written with owner-only permissions.
- Versioned JSON envelopes allow safe format evolution.

This is an educational project and has not received an external security audit.

## Use

```bash
go test ./...
go run ./cmd/vaultdrop keygen --out keys
go run ./cmd/vaultdrop encrypt --key keys/vaultdrop-public.pem --in report.pdf --out report.vault --name report.pdf
go run ./cmd/vaultdrop decrypt --key keys/vaultdrop-private.pem --in report.vault --out recovered.pdf --name report.pdf
```

## Resume bullet

Implemented a secure file-sharing CLI in Go using envelope encryption (RSA-OAEP and AES-256-GCM), authenticated metadata, strict key permissions, and tamper-detection tests.
