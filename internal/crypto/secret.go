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

func NewSecret(data []byte) (*Secret, error) {
	s := NewSession()
	e, err := s.Seal(data)
	if err != nil {
		s.Destroy()
	}
	return e, err
}

func (e *Secret) Destroy() { e.session.Destroy() }

func (e *Secret) Size() int { return len(e.ct) - TagLen }
