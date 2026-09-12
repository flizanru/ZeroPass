package vault

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var defaultPathProvider = DefaultPath
var legacyPathProvider = legacyVaultPath

func legacyVaultPath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return filepath.Join(filepath.Dir(exe), FileName), nil
}

// MigrateLegacy copies a valid vault from the historical executable directory
// to the protected per-user data directory. The new location always wins.
func MigrateLegacy() (moved bool, warning string, err error) {
	newPath, err := defaultPathProvider()
	if err != nil {
		return false, "", err
	}
	oldPath, err := legacyPathProvider()
	if err != nil {
		return false, "", err
	}
	if strings.EqualFold(filepath.Clean(newPath), filepath.Clean(oldPath)) {
		return false, "", nil
	}
	err = withWriteLock(newPath, func() error {
		if _, statErr := os.Lstat(newPath); statErr == nil {
			return nil
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return statErr
		}
		old, readErr := readFile(oldPath)
		if errors.Is(readErr, os.ErrNotExist) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
		if _, _, _, _, _, parseErr := parseFile(old); parseErr != nil {
			return parseErr
		}
		var oldBackup []byte
		if backup, backupErr := readFile(oldPath + BackupSuffix); backupErr == nil {
			if _, _, _, _, _, parseErr := parseFile(backup); parseErr != nil {
				return fmt.Errorf("резервная копия старого хранилища: %w", parseErr)
			}
			oldBackup = backup
		} else if !errors.Is(backupErr, os.ErrNotExist) {
			return backupErr
		}
		if writeErr := writeAtomic(newPath, old); writeErr != nil {
			return writeErr
		}
		cleanupNew := true
		defer func() {
			if cleanupNew {
				_ = os.Remove(newPath)
				_ = os.Remove(newPath + BackupSuffix)
			}
		}()
		if oldBackup != nil {
			if writeErr := writeAtomic(newPath+BackupSuffix, oldBackup); writeErr != nil {
				return writeErr
			}
		}
		check, readErr := readFile(newPath)
		if readErr != nil || !bytes.Equal(check, old) {
			if readErr != nil {
				return readErr
			}
			return errors.New("проверка перенесённого хранилища не совпала")
		}
		cleanupNew = false
		moved = true
		var removalFailures []string
		for _, candidate := range []string{oldPath, oldPath + BackupSuffix} {
			if removeErr := os.Remove(candidate); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				removalFailures = append(removalFailures, candidate)
			}
		}
		warning = "Старая копия хранилища находилась в общедоступном каталоге и могла быть прочитана другими пользователями; рекомендуется сменить мастер-пароль."
		if len(removalFailures) > 0 {
			warning += " Не удалось удалить старый файл; удалите вручную: " + strings.Join(removalFailures, ", ")
		}
		return nil
	})
	return moved, warning, err
}
