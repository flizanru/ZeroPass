package vault

import (
	"encoding/binary"
	"errors"
)

const (
	maxEntries  = 100_000
	maxFieldLen = 1 << 20
)

var errCodec = errors.New("повреждённые данные хранилища")

type EntryMeta struct {
	ID       int64
	Title    string
	Username string
	URL      string
}

type entryFields struct {
	title, username, url, notes, password []byte
}

func decodeEntries(data []byte, fn func(entryFields) error) error {
	if len(data) < 4 {
		return errCodec
	}
	n := binary.LittleEndian.Uint32(data)
	if uint64(n) > maxEntries {
		return errCodec
	}
	off := 4
	readField := func() ([]byte, error) {
		if off+4 > len(data) {
			return nil, errCodec
		}
		l := int(binary.LittleEndian.Uint32(data[off:]))
		off += 4
		if l > maxFieldLen || off+l > len(data) {
			return nil, errCodec
		}
		f := data[off : off+l]
		off += l
		return f, nil
	}
	for i := uint32(0); i < n; i++ {
		var e entryFields
		var err error
		if e.title, err = readField(); err != nil {
			return err
		}
		if e.username, err = readField(); err != nil {
			return err
		}
		if e.url, err = readField(); err != nil {
			return err
		}
		if e.notes, err = readField(); err != nil {
			return err
		}
		if e.password, err = readField(); err != nil {
			return err
		}
		if err := fn(e); err != nil {
			return err
		}
	}
	if off != len(data) {
		return errCodec
	}
	return nil
}
