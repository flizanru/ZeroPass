package secure

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procSetWindowDisplayAffinity = user32.NewProc("SetWindowDisplayAffinity")
	procGetWindowDisplayAffinity = user32.NewProc("GetWindowDisplayAffinity")
)

const wdaExcludeFromCapture = 0x0000_0011

func ProtectHWND(hwnd uintptr) error {
	if hwnd == 0 {
		return errors.New("нулевой дескриптор окна")
	}
	r, _, callErr := procSetWindowDisplayAffinity.Call(hwnd, wdaExcludeFromCapture)
	if r == 0 {
		return fmt.Errorf("SetWindowDisplayAffinity: %v (нужна Windows 10 2004+)", callErr)
	}

	var aff uint32
	r, _, _ = procGetWindowDisplayAffinity.Call(hwnd, uintptr(unsafe.Pointer(&aff)))
	if r == 0 || aff != wdaExcludeFromCapture {
		return fmt.Errorf("защита не подтверждена: GetWindowDisplayAffinity=0x%x", aff)
	}
	return nil
}
