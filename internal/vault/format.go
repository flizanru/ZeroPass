package vault

import (
	"encoding/binary"
	"errors"
	"fmt"

	"zeropass/internal/crypto"
)

const (
	magic       = "ZPWVLT01"
	version     = 1
	headerLen   = 8 + 1 + 4 + 4 + 1 + crypto.SaltLen
	minFileLen  = headerLen + crypto.NonceLen + crypto.TagLen
	maxFileLen  = 256 << 20
	maxPlainLen = maxFileLen - minFileLen
)

var ErrFormat = errors.New("данные не поддерживаются ZeroPass или повреждены")
var ErrTooLarge = errors.New("размер хранилища превышает допустимые 256 MiB")

func encodeHeader(p crypto.KDFParams, salt []byte) []byte {
	h := make([]byte, headerLen)
	copy(h[0:8], magic)
	h[8] = version
	binary.LittleEndian.PutUint32(h[9:13], p.MemoryKiB)
	binary.LittleEndian.PutUint32(h[13:17], p.Time)
	h[17] = p.Threads
	copy(h[18:], salt)
	return h
}

func parseFile(data []byte) (p crypto.KDFParams, header, salt, nonce, ct []byte, err error) {
	if len(data) < minFileLen || len(data) > maxFileLen {
		err = ErrFormat
		return
	}
	if string(data[0:8]) != magic {
		err = ErrFormat
		return
	}
	if data[8] != version {
		err = fmt.Errorf("%w: неподдерживаемая версия формата %d", ErrFormat, data[8])
		return
	}
	p = crypto.KDFParams{
		MemoryKiB: binary.LittleEndian.Uint32(data[9:13]),
		Time:      binary.LittleEndian.Uint32(data[13:17]),
		Threads:   data[17],
	}

	if vErr := p.Validate(); vErr != nil {
		err = fmt.Errorf("%w: %v", ErrFormat, vErr)
		return
	}
	header = data[:headerLen]
	salt = data[18:headerLen]
	nonce = data[headerLen : headerLen+crypto.NonceLen]
	ct = data[headerLen+crypto.NonceLen:]
	return
}
