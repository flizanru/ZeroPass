//go:build windows && amd64

package crypto

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

const SodiumSHA256 = "f1b5581777aaace74f76c5fea5733e4a1245048f4b299b20b9692005e469978b"

var sodium struct {
	sync.RWMutex
	dll              *windows.DLL
	file             *os.File
	encrypt, decrypt *windows.Proc
}

func verifiedDLL(path string) (*os.File, string, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, "", err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, "", err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, "", fmt.Errorf("открытие libsodium.dll: %w", err)
	}
	file := os.NewFile(uintptr(h), path)
	digest := sha256.New()
	_, err = io.Copy(digest, io.LimitReader(file, 4<<20))
	if err != nil || fmt.Sprintf("%x", digest.Sum(nil)) != SodiumSHA256 {
		file.Close()
		return nil, "", errors.New("libsodium.dll отсутствует, повреждена или имеет неподдерживаемую версию")
	}
	return file, path, nil
}

func InitSodium(path string) error {
	sodium.Lock()
	defer sodium.Unlock()
	if sodium.dll != nil {
		return nil
	}
	file, path, err := verifiedDLL(path)
	if err != nil {
		return err
	}
	h, err := windows.LoadLibraryEx(path, 0, windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		file.Close()
		return fmt.Errorf("загрузка libsodium.dll: %w", err)
	}
	dll := &windows.DLL{Name: path, Handle: h}
	fail := func(err error) error { dll.Release(); file.Close(); return err }
	init, err := dll.FindProc("sodium_init")
	if err != nil {
		return fail(err)
	}
	enc, err := dll.FindProc("crypto_aead_xchacha20poly1305_ietf_encrypt")
	if err != nil {
		return fail(err)
	}
	dec, err := dll.FindProc("crypto_aead_xchacha20poly1305_ietf_decrypt")
	if err != nil {
		return fail(err)
	}
	if r, _, _ := init.Call(); int32(r) < 0 {
		return fail(errors.New("инициализация libsodium не удалась"))
	}
	sodium.dll, sodium.file, sodium.encrypt, sodium.decrypt = dll, file, enc, dec
	return nil
}

func sodiumEncrypt(out, plaintext, aad, nonce, key []byte) error {
	sodium.RLock()
	defer sodium.RUnlock()
	if sodium.encrypt == nil {
		return errors.New("libsodium не инициализирована")
	}
	r, _, _ := sodium.encrypt.Call(
		uintptr(unsafe.Pointer(unsafe.SliceData(out))), 0,
		uintptr(unsafe.Pointer(unsafe.SliceData(plaintext))), uintptr(len(plaintext)),
		uintptr(unsafe.Pointer(unsafe.SliceData(aad))), uintptr(len(aad)),
		0, uintptr(unsafe.Pointer(unsafe.SliceData(nonce))), uintptr(unsafe.Pointer(unsafe.SliceData(key))))
	runtime.KeepAlive(out)
	runtime.KeepAlive(plaintext)
	runtime.KeepAlive(aad)
	runtime.KeepAlive(nonce)
	runtime.KeepAlive(key)
	if int32(r) != 0 {
		return errors.New("шифрование libsodium не удалось")
	}
	return nil
}

func sodiumDecrypt(out, ct, aad, nonce, key []byte) error {
	sodium.RLock()
	defer sodium.RUnlock()
	if sodium.decrypt == nil {
		return errors.New("libsodium не инициализирована")
	}
	r, _, _ := sodium.decrypt.Call(
		uintptr(unsafe.Pointer(unsafe.SliceData(out))), 0, 0,
		uintptr(unsafe.Pointer(unsafe.SliceData(ct))), uintptr(len(ct)),
		uintptr(unsafe.Pointer(unsafe.SliceData(aad))), uintptr(len(aad)),
		uintptr(unsafe.Pointer(unsafe.SliceData(nonce))), uintptr(unsafe.Pointer(unsafe.SliceData(key))))
	runtime.KeepAlive(out)
	runtime.KeepAlive(ct)
	runtime.KeepAlive(aad)
	runtime.KeepAlive(nonce)
	runtime.KeepAlive(key)
	if int32(r) != 0 {
		return ErrDecrypt
	}
	return nil
}
