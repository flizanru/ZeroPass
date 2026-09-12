package crypto

import (
	"crypto/rand"
	"fmt"
	"runtime/debug"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/argon2"
)

const (
	KeyLen  = 32
	SaltLen = 16
)

type KDFParams struct {
	MemoryKiB uint32
	Time      uint32
	Threads   uint8
}

var DefaultKDFParams = KDFParams{MemoryKiB: 64 * 1024, Time: 3, Threads: 4}

func (p KDFParams) Validate() error {
	switch {
	case p.MemoryKiB < 8*1024:
		return fmt.Errorf("память KDF занижена: %d KiB (минимум 8 MiB)", p.MemoryKiB)
	case p.MemoryKiB > 256*1024:
		return fmt.Errorf("память KDF завышена: %d KiB (максимум 256 MiB)", p.MemoryKiB)
	case p.Time == 0 || p.Time > 64:
		return fmt.Errorf("недопустимое число итераций KDF: %d", p.Time)
	case p.Threads == 0 || p.Threads > 32:
		return fmt.Errorf("недопустимый параллелизм KDF: %d", p.Threads)
	case uint64(p.MemoryKiB)*uint64(p.Time) > 768*1024:
		return fmt.Errorf("стоимость KDF превышает бюджет 768 MiB-проходов")
	}
	return nil
}

func NewSalt() ([]byte, error) {
	s := make([]byte, SaltLen)
	if _, err := rand.Read(s); err != nil {
		return nil, fmt.Errorf("CSPRNG недоступен: %w", err)
	}
	return s, nil
}

func DeriveKey(password *memguard.LockedBuffer, salt []byte, p KDFParams) (*Secret, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if len(salt) != SaltLen {
		return nil, fmt.Errorf("длина соли %d, ожидалось %d", len(salt), SaltLen)
	}
	key := argon2.IDKey(password.Bytes(), salt, p.Time, p.MemoryKiB, p.Threads, KeyLen)
	enc, err := NewSecret(key)

	debug.FreeOSMemory()
	return enc, err
}
