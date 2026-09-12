//go:build !windows

package secure

import "errors"

func ProtectHWND(_ uintptr) error {
	return errors.New("маскировка окна от захвата экрана реализована только для Windows")
}

func DarkTitleBar(_ uintptr) error {
	return errors.New("тёмный заголовок окна доступен только в сборке для Windows")
}
