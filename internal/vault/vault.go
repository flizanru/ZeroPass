package vault

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/awnumar/memguard"
	"os"
	"zeropass/internal/crypto"
)

var ErrConflict = errors.New("хранилище изменено другим экземпляром; заблокируйте и откройте его заново")
var ErrExists = errors.New("хранилище или резервная копия уже существуют")

type Vault struct {
	Path       string
	Params     crypto.KDFParams
	Salt       []byte
	key        *crypto.Secret
	keySession *crypto.Session
	Store      *Store
	path       string
	header     []byte
	revision   [32]byte
	persisted  bool
}

func Create(path string, password *memguard.LockedBuffer) (*Vault, error) {
	path, err := canonicalPath(path)
	if err != nil {
		return nil, err
	}
	salt, err := crypto.NewSalt()
	if err != nil {
		return nil, err
	}
	key, keySession, err := crypto.DeriveKey(password, salt, crypto.DefaultKDFParams)
	if err != nil {
		return nil, err
	}
	st, err := newStore()
	if err != nil {
		keySession.Destroy()
		return nil, err
	}
	v := &Vault{Path: path, path: path, Params: crypto.DefaultKDFParams, Salt: salt, key: key, keySession: keySession, Store: st, header: encodeHeader(crypto.DefaultKDFParams, salt)}
	if err := v.Save(); err != nil {
		v.Lock()
		return nil, fmt.Errorf("создание хранилища: %w", err)
	}
	return v, nil
}

func Unlock(path string, password *memguard.LockedBuffer) (*Vault, error) {
	path, err := canonicalPath(path)
	if err != nil {
		return nil, err
	}
	var data []byte
	err = withWriteLock(func() error {
		var err error
		if err = rejectHardLinks(path); err != nil {
			return err
		}
		data, err = readFile(path)
		return err
	})
	if err != nil {
		return nil, err
	}
	params, header, salt, nonce, ct, err := parseFile(data)
	if err != nil {
		return nil, err
	}
	key, keySession, err := crypto.DeriveKey(password, salt, params)
	if err != nil {
		return nil, err
	}
	plain, err := crypto.Open(key, nonce, ct, header)
	if err != nil {
		keySession.Destroy()
		return nil, err
	}
	defer plain.Destroy()
	st, err := newStore()
	if err != nil {
		keySession.Destroy()
		return nil, err
	}
	if err := st.load(plain.Bytes()); err != nil {
		st.Close()
		keySession.Destroy()
		return nil, fmt.Errorf("загрузка записей: %w", err)
	}
	return &Vault{Path: path, path: path, Params: params, Salt: append([]byte(nil), salt...), key: key, keySession: keySession, Store: st, header: append([]byte(nil), header...), revision: sha256.Sum256(data), persisted: true}, nil
}

func (v *Vault) Save() error { return v.save(v.Store) }

func (v *Vault) Update(change func(*Store) error) error {
	if v.key == nil || v.Store == nil {
		return crypto.ErrLocked
	}
	candidate := v.Store.clone()
	if err := change(candidate); err != nil {
		candidate.wipeValues()
		return err
	}
	if err := v.save(candidate); err != nil {
		candidate.wipeValues()
		return err
	}
	for _, secret := range v.Store.pw {
		secret.Wipe()
	}
	for _, secret := range v.Store.notes {
		secret.Wipe()
	}
	v.Store.metas, v.Store.pw, v.Store.notes, v.Store.nextID = candidate.metas, candidate.pw, candidate.notes, candidate.nextID
	return nil
}

func (v *Vault) save(st *Store) error {
	if v.key == nil || st == nil {
		return crypto.ErrLocked
	}
	plain, err := st.serialize()
	if err != nil {
		return err
	}
	defer plain.Destroy()
	nonce, ct, err := crypto.Seal(v.key, plain.Bytes(), v.header)
	if err != nil {
		return err
	}
	out := make([]byte, 0, len(v.header)+len(nonce)+len(ct))
	out = append(out, v.header...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return withWriteLock(func() error {
		if err := rejectHardLinks(v.path); err != nil {
			return err
		}
		if v.persisted {
			current, err := readFile(v.path)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrConflict, err)
			}
			if sha256.Sum256(current) != v.revision {
				return ErrConflict
			}
		} else {
			for _, name := range []string{v.path, v.path + BackupSuffix} {
				if _, err := os.Lstat(name); err == nil {
					return ErrExists
				} else if !errors.Is(err, os.ErrNotExist) {
					return err
				}
			}
		}
		if err := writeAtomic(v.path, out); err != nil {
			return err
		}
		v.revision, v.persisted = sha256.Sum256(out), true
		return nil
	})
}

func (v *Vault) Lock() {
	if v.Store != nil {
		v.Store.Close()
		v.Store = nil
	}
	if v.keySession != nil {
		v.keySession.Destroy()
		v.keySession = nil
	}
	v.key = nil
}

func Recover(path string) error {
	path, err := canonicalPath(path)
	if err != nil {
		return err
	}
	return withWriteLock(func() error {
		if _, err := os.Lstat(path); err == nil {
			return ErrExists
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		data, err := readFile(path + BackupSuffix)
		if err != nil {
			return err
		}
		if _, _, _, _, _, err := parseFile(data); err != nil {
			return err
		}
		return writeAtomic(path, data)
	})
}
