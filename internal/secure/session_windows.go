package secure

import (
	"golang.org/x/sys/windows"
	"runtime"
	"strings"
	"unsafe"
)

var (
	procIsIconic                 = user32.NewProc("IsIconic")
	procOpenInputDesktop         = user32.NewProc("OpenInputDesktop")
	procCloseDesktop             = user32.NewProc("CloseDesktop")
	procGetUserObjectInformation = user32.NewProc("GetUserObjectInformationW")
)

func SessionUnavailable(hwnd uintptr) bool {
	if r, _, _ := procIsIconic.Call(hwnd); r != 0 {
		return true
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	desktop, _, _ := procOpenInputDesktop.Call(0, 0, 1)
	if desktop == 0 {
		return true
	}
	defer procCloseDesktop.Call(desktop)
	var name [256]uint16
	var needed uint32
	r, _, _ := procGetUserObjectInformation.Call(desktop, 2, uintptr(unsafe.Pointer(&name[0])), uintptr(len(name)*2), uintptr(unsafe.Pointer(&needed)))
	return r == 0 || !strings.EqualFold(windows.UTF16ToString(name[:]), "Default")
}
