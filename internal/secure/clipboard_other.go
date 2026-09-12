//go:build !windows

package secure

import (
	"errors"
	"time"
)

func CopySensitive(_ uintptr, _ []byte, _ time.Duration) (string, error) {
	return "", errors.New("копирование в буфер обмена доступно только в сборке для Windows")
}

func ClearClipboardIfOwned() error { return nil }
func WaitForClipboardClear()       {}
