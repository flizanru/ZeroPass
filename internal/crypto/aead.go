package crypto

import (
	"crypto/rand"
	"errors"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	NonceLen = 24
	TagLen   = 16
)

var _ = [1]struct{}{}[NonceLen-chacha20poly1305.NonceSizeX]
var _ = [1]struct{}{}[TagLen-chacha20poly1305.Overhead]
var _ = [1]struct{}{}[KeyLen-chacha20poly1305.KeySize]

var ErrDecrypt = errors.New("неверный мастер-пароль или файл повреждён")

func Seal(key *Secret, plaintext, aad []byte) (nonce, ct []byte, err error) {
	kb, err := key.Open()
	if err != nil {
		return nil, nil, err
	}
	defer kb.Destroy()
	return sealBytes(kb.Bytes(), plaintext, aad)
}

func Open(key *Secret, nonce, ct, aad []byte) (*memguard.LockedBuffer, error) {
	kb, err := key.Open()
	if err != nil {
		return nil, err
	}
	defer kb.Destroy()
	return openBytes(kb.Bytes(), nonce, ct, aad)
}

func sealBytes(key, plaintext, aad []byte) (nonce, ct []byte, err error) {
	if len(key) != KeyLen {
		return nil, nil, ErrLocked
	}
	nonce = make([]byte, NonceLen)
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ct = make([]byte, len(plaintext)+TagLen)
	if err = aeadSeal(ct, plaintext, aad, nonce, key); err != nil {
		return nil, nil, err
	}
	return nonce, ct, nil
}

func openBytes(key, nonce, ct, aad []byte) (*memguard.LockedBuffer, error) {
	if len(key) != KeyLen || len(nonce) != NonceLen || len(ct) <= TagLen {
		return nil, ErrDecrypt
	}
	out := memguard.NewBuffer(len(ct) - TagLen)
	if err := aeadOpen(out.Bytes(), ct, aad, nonce, key); err != nil {
		out.Destroy()
		return nil, err
	}
	return out, nil
}
