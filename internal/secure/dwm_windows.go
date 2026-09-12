package secure

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	dwmwaUseImmersiveDarkMode      = 20
	dwmwaUseImmersiveDarkModePre20 = 19
)

var (
	dwmapi                    = windows.NewLazySystemDLL("dwmapi.dll")
	procDwmSetWindowAttribute = dwmapi.NewProc("DwmSetWindowAttribute")
)

func DarkTitleBar(hwnd uintptr) error {
	if hwnd == 0 {
		return errors.New("нулевой дескриптор окна")
	}
	enabled := int32(1)
	for _, attr := range []uintptr{dwmwaUseImmersiveDarkMode, dwmwaUseImmersiveDarkModePre20} {
		r, _, _ := procDwmSetWindowAttribute.Call(hwnd, attr, uintptr(unsafe.Pointer(&enabled)), 4)
		if r == 0 {
			return nil
		}
	}
	return errors.New("DwmSetWindowAttribute: тёмный заголовок не поддерживается системой")
}
