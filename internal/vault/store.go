package vault

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/awnumar/memguard"
	"zeropass/internal/crypto"
)

type Store struct {
	metas   []EntryMeta
	pw      map[int64]*crypto.Secret
	notes   map[int64]*crypto.Secret
	session *crypto.Session
	nextID  int64
}

func newStore() (*Store, error) {
	return &Store{pw: make(map[int64]*crypto.Secret), notes: make(map[int64]*crypto.Secret), session: crypto.NewSession(), nextID: 1}, nil
}

func (s *Store) load(plain []byte) error {
	return decodeEntries(plain, func(e entryFields) error {
		id := s.nextID
		s.nextID++
		s.metas = append(s.metas, EntryMeta{
			ID:       id,
			Title:    string(e.title),
			Username: string(e.username),
			URL:      string(e.url),
		})
		if len(e.notes) > 0 {
			secret, err := s.session.Seal(e.notes)
			if err != nil {
				return err
			}
			s.notes[id] = secret
		}
		if len(e.password) > 0 {
			secret, err := s.session.Seal(e.password)
			if err != nil {
				return err
			}
			s.pw[id] = secret
		}
		return nil
	})
}

func (s *Store) indexOf(id int64) int {
	for i := range s.metas {
		if s.metas[i].ID == id {
			return i
		}
	}
	return -1
}

func validateMeta(m EntryMeta) error {
	if strings.TrimSpace(m.Title) == "" {
		return errors.New("название записи не может быть пустым")
	}
	for _, f := range []string{m.Title, m.Username, m.URL} {
		if len(f) > maxFieldLen {
			return fmt.Errorf("поле длиннее %d байт", maxFieldLen)
		}
	}
	return nil
}

func (s *Store) List() ([]EntryMeta, error) {
	out := make([]EntryMeta, len(s.metas))
	for i := range s.metas {
		out[len(s.metas)-1-i] = s.metas[i]
	}
	return out, nil
}

func (s *Store) Get(id int64) (EntryMeta, error) {
	if i := s.indexOf(id); i >= 0 {
		return s.metas[i], nil
	}
	return EntryMeta{}, fmt.Errorf("запись %d не найдена", id)
}

func (s *Store) Add(m EntryMeta, password []byte) (int64, error) {
	defer memguard.WipeBytes(password)
	if err := validateMeta(m); err != nil {
		return 0, err
	}
	if len(password) == 0 {
		return 0, errors.New("пароль записи не может быть пустым")
	}
	if len(password) > maxFieldLen {
		return 0, fmt.Errorf("пароль длиннее %d байт", maxFieldLen)
	}
	if len(s.metas) >= maxEntries {
		return 0, fmt.Errorf("достигнут предел записей: %d", maxEntries)
	}
	id := s.nextID
	secret, err := s.session.Seal(password)
	if err != nil {
		return 0, err
	}
	s.nextID++
	m.ID = id
	s.metas = append(s.metas, m)
	s.pw[id] = secret
	return id, nil
}

func (s *Store) UpdateMeta(m EntryMeta) error {
	if err := validateMeta(m); err != nil {
		return err
	}
	i := s.indexOf(m.ID)
	if i < 0 {
		return fmt.Errorf("запись %d не найдена", m.ID)
	}
	s.metas[i] = m
	return nil
}

func (s *Store) SetPassword(id int64, password []byte) error {
	defer memguard.WipeBytes(password)
	if len(password) == 0 {
		return errors.New("пароль записи не может быть пустым")
	}
	if len(password) > maxFieldLen {
		return fmt.Errorf("пароль длиннее %d байт", maxFieldLen)
	}
	if s.indexOf(id) < 0 {
		return fmt.Errorf("запись %d не найдена", id)
	}
	secret, err := s.session.Seal(password)
	if err != nil {
		return err
	}
	if old := s.pw[id]; old != nil {
		old.Wipe()
	}
	s.pw[id] = secret
	return nil
}

func (s *Store) Password(id int64) (*memguard.LockedBuffer, error) {
	e, ok := s.pw[id]
	if !ok {
		return nil, fmt.Errorf("пароль записи %d отсутствует", id)
	}
	b, err := e.Open()
	if err != nil {
		return nil, fmt.Errorf("открытие анклава записи %d: %w", id, err)
	}
	return b, nil
}

// Notes returns a newly materialized locked buffer. An absent/empty note is
// represented by nil, nil so callers need not allocate a zero-length secret.
func (s *Store) Notes(id int64) (*memguard.LockedBuffer, error) {
	if s == nil || s.session == nil || s.indexOf(id) < 0 {
		return nil, crypto.ErrLocked
	}
	e, ok := s.notes[id]
	if !ok {
		return nil, nil
	}
	b, err := e.Open()
	if err != nil {
		return nil, fmt.Errorf("открытие заметки записи %d: %w", id, err)
	}
	return b, nil
}

func (s *Store) SetNotes(id int64, notes []byte) error {
	defer memguard.WipeBytes(notes)
	if len(notes) > maxFieldLen {
		return fmt.Errorf("заметка длиннее %d байт", maxFieldLen)
	}
	if s.indexOf(id) < 0 {
		return fmt.Errorf("запись %d не найдена", id)
	}
	if old := s.notes[id]; old != nil {
		old.Wipe()
		delete(s.notes, id)
	}
	if len(notes) == 0 {
		return nil
	}
	secret, err := s.session.Seal(notes)
	if err != nil {
		return err
	}
	s.notes[id] = secret
	return nil
}

func (s *Store) Delete(id int64) error {
	if i := s.indexOf(id); i >= 0 {
		s.metas = append(s.metas[:i], s.metas[i+1:]...)
	}
	if secret := s.pw[id]; secret != nil {
		secret.Wipe()
	}
	if secret := s.notes[id]; secret != nil {
		secret.Wipe()
	}
	delete(s.pw, id)
	delete(s.notes, id)
	return nil
}

func (s *Store) Count() (int, error) {
	return len(s.metas), nil
}

func (s *Store) serialize() (*memguard.LockedBuffer, error) {
	metas := s.metas
	if len(metas) > maxEntries {
		return nil, fmt.Errorf("слишком много записей: %d", len(metas))
	}

	size := 4
	for _, m := range metas {
		fields := []int{len(m.Title), len(m.Username), len(m.URL), 0, 0}
		if e, ok := s.notes[m.ID]; ok {
			fields[3] = e.Size()
		}
		if e, ok := s.pw[m.ID]; ok {
			fields[4] = e.Size()
		}
		for _, n := range fields {
			if n < 0 || n > maxFieldLen || size > maxPlainLen-4 || n > maxPlainLen-size-4 {
				return nil, ErrTooLarge
			}
			size += 4 + n
		}
	}

	out := memguard.NewBuffer(size)
	buf := out.Bytes()
	binary.LittleEndian.PutUint32(buf, uint32(len(metas)))
	off := 4
	put := func(f []byte) {
		binary.LittleEndian.PutUint32(buf[off:], uint32(len(f)))
		off += 4
		off += copy(buf[off:], f)
	}

	for _, m := range metas {
		put([]byte(m.Title))
		put([]byte(m.Username))
		put([]byte(m.URL))
		if e, ok := s.notes[m.ID]; ok {
			b, err := e.Open()
			if err != nil {
				out.Destroy()
				return nil, fmt.Errorf("анклав заметки %d: %w", m.ID, err)
			}
			put(b.Bytes())
			b.Destroy()
		} else {
			put(nil)
		}
		if e, ok := s.pw[m.ID]; ok {
			b, err := e.Open()
			if err != nil {
				out.Destroy()
				return nil, fmt.Errorf("анклав записи %d: %w", m.ID, err)
			}
			put(b.Bytes())
			b.Destroy()
		} else {
			put(nil)
		}
	}
	if off != size {
		out.Destroy()
		return nil, errors.New("несогласованный размер снимка (запись изменена во время сериализации?)")
	}
	return out, nil
}

func (s *Store) Close() {
	s.wipeValues()
	if s.session != nil {
		s.session.Destroy()
	}
	s.metas = nil
	s.session = nil
}

func (s *Store) wipeValues() {
	for _, secret := range s.pw {
		secret.Wipe()
	}
	for _, secret := range s.notes {
		secret.Wipe()
	}
	s.pw = nil
	s.notes = nil
}

func (s *Store) clone() *Store {
	// The session is shared with the original. Per-value ciphertext is copied so
	// wiping a failed transaction cannot damage the live store; the clone must
	// never destroy the shared session.
	c := &Store{metas: append([]EntryMeta(nil), s.metas...), pw: make(map[int64]*crypto.Secret, len(s.pw)), notes: make(map[int64]*crypto.Secret, len(s.notes)), session: s.session, nextID: s.nextID}
	for id, secret := range s.pw {
		c.pw[id] = secret.Clone()
	}
	for id, secret := range s.notes {
		c.notes[id] = secret.Clone()
	}
	return c
}
