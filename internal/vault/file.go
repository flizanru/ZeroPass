package vault

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	FileName     = "vault.zpw"
	BackupSuffix = ".bak"
)

func DefaultPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("путь к исполняемому файлу: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return filepath.Join(filepath.Dir(exe), FileName), nil
}

func readFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxFileLen {
		return nil, ErrFormat
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFileLen+1))
	if err != nil {
		return nil, fmt.Errorf("чтение %s: %w", path, err)
	}
	if len(data) > maxFileLen {
		return nil, ErrTooLarge
	}
	return data, nil
}

func prepareFile(dir string, data []byte) (name string, err error) {
	tmp, err := os.CreateTemp(dir, ".zpw-tmp-*")
	if err != nil {
		return "", err
	}
	name = tmp.Name()
	defer func() {
		_ = tmp.Close()
		if err != nil {
			_ = os.Remove(name)
		}
	}()
	if _, err = tmp.Write(data); err != nil {
		return name, err
	}
	if err = tmp.Sync(); err != nil {
		return name, err
	}
	if err = tmp.Close(); err != nil {
		return name, err
	}
	back, err := readFile(name)
	if err != nil {
		return name, err
	}
	if !bytes.Equal(back, data) {
		return name, errors.New("контрольное чтение не совпало; файл хранилища не заменён")
	}
	return name, nil
}

func writeAtomic(path string, data []byte) error {
	if len(data) > maxFileLen {
		return ErrTooLarge
	}
	tmp, err := prepareFile(filepath.Dir(path), data)
	if err != nil {
		return fmt.Errorf("подготовка снимка: %w", err)
	}
	defer os.Remove(tmp)
	old, err := readFile(path)
	if err == nil {
		bak, err := prepareFile(filepath.Dir(path), old)
		if err != nil {
			return fmt.Errorf("подготовка резервной копии: %w", err)
		}
		defer os.Remove(bak)
		if err := replaceFile(bak, path+BackupSuffix); err != nil {
			return fmt.Errorf("замена резервной копии: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := replaceFile(tmp, path); err != nil {
		return fmt.Errorf("замена хранилища: %w", err)
	}
	return nil
}
