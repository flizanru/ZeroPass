package crypto

import (
	"crypto/cipher"
	"errors"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

// This deliberately does not use chacha20poly1305.NewX: at
// xchacha20poly1305.go:31-33 NewX copies the file key into an ordinary Go heap
// object that has no wipe operation. We derive a nonce-specific subkey first,
// keep its authoritative copy in locked memory, and limit the unavoidable heap
// copy inside chacha20poly1305.New to a single operation.
func xchachaAEAD(key, nonce []byte) (cipher.AEAD, []byte, func(), error) {
	if len(key) != KeyLen || len(nonce) != NonceLen {
		return nil, nil, nil, errors.New("invalid XChaCha20-Poly1305 key or nonce length")
	}
	hKey, err := chacha20.HChaCha20(key, nonce[:16])
	if err != nil {
		return nil, nil, nil, err
	}
	subkey := memguard.NewBuffer(KeyLen)
	copy(subkey.Bytes(), hKey)
	memguard.WipeBytes(hKey)
	cNonce := make([]byte, chacha20poly1305.NonceSize)
	copy(cNonce[4:], nonce[16:])
	aead, err := chacha20poly1305.New(subkey.Bytes())
	if err != nil {
		subkey.Destroy()
		return nil, nil, nil, err
	}
	return aead, cNonce, subkey.Destroy, nil
}

func aeadSeal(out, plaintext, aad, nonce, key []byte) error {
	if len(out) != len(plaintext)+TagLen {
		return errors.New("invalid XChaCha20-Poly1305 output length")
	}
	aead, cNonce, destroy, err := xchachaAEAD(key, nonce)
	if err != nil {
		return err
	}
	defer destroy()
	res := aead.Seal(out[:0], cNonce, plaintext, aad)
	if len(res) != len(out) || len(out) > 0 && &res[0] != &out[0] {
		return errors.New("XChaCha20-Poly1305 unexpectedly allocated output")
	}
	return nil
}

func aeadOpen(out, ciphertext, aad, nonce, key []byte) error {
	if len(ciphertext) < TagLen || len(out) != len(ciphertext)-TagLen {
		memguard.WipeBytes(out)
		return ErrDecrypt
	}
	aead, cNonce, destroy, err := xchachaAEAD(key, nonce)
	if err != nil {
		memguard.WipeBytes(out)
		return ErrDecrypt
	}
	defer destroy()
	res, err := aead.Open(out[:0], cNonce, ciphertext, aad)
	if err != nil {
		memguard.WipeBytes(out)
		return ErrDecrypt
	}
	if len(res) != len(out) || len(out) > 0 && &res[0] != &out[0] {
		memguard.WipeBytes(out)
		return ErrDecrypt
	}
	return nil
}
