package crypto

import (
	"errors"
	"sync"

	"github.com/awnumar/memguard"
)

var ErrLocked = errors.New("ключ сеанса уничтожен")

type Session struct {
	mu  sync.Mutex
	key *memguard.LockedBuffer
}

type Secret struct {
	session   *Session
	nonce, ct []byte
}

func NewSession() *Session {
	return &Session{key: memguard.NewBufferRandom(KeyLen)}
}

func (s *Session) Seal(data []byte) (*Secret, error) {
	defer memguard.WipeBytes(data)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key == nil || !s.key.IsAlive() {
		return nil, ErrLocked
	}
	nonce, ct, err := sealBytes(s.key.Bytes(), data, nil)
	if err != nil {
		return nil, err
	}
	return &Secret{session: s, nonce: nonce, ct: ct}, nil
}

func (e *Secret) Open() (*memguard.LockedBuffer, error) {
	s := e.session
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key == nil || !s.key.IsAlive() {
		return nil, ErrLocked
	}
	return openBytes(s.key.Bytes(), e.nonce, e.ct, nil)
}

func (s *Session) Destroy() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key != nil {
		s.key.Destroy()
		s.key = nil
	}
}

func NewSecret(data []byte) (*Secret, *Session, error) {
	s := NewSession()
	e, err := s.Seal(data)
	if err != nil {
		s.Destroy()
		return nil, nil, err
	}
	return e, s, nil
}

// Wipe destroys this encrypted value without revoking other secrets that share
// its session.
func (e *Secret) Wipe() {
	if e == nil {
		return
	}
	memguard.WipeBytes(e.nonce)
	memguard.WipeBytes(e.ct)
	e.nonce = nil
	e.ct = nil
}

// Clone duplicates only the per-value ciphertext. The session remains shared;
// the caller must never destroy it through the clone.
func (e *Secret) Clone() *Secret {
	if e == nil {
		return nil
	}
	return &Secret{
		session: e.session,
		nonce:   append([]byte(nil), e.nonce...),
		ct:      append([]byte(nil), e.ct...),
	}
}

func (e *Secret) Size() int {
	if e == nil || len(e.ct) < TagLen {
		return 0
	}
	return len(e.ct) - TagLen
}
