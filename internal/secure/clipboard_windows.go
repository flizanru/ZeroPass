package secure

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procOpenClipboard      = user32.NewProc("OpenClipboard")
	procCloseClipboard     = user32.NewProc("CloseClipboard")
	procEmptyClipboard     = user32.NewProc("EmptyClipboard")
	procSetClipboardData   = user32.NewProc("SetClipboardData")
	procRegisterClipFormat = user32.NewProc("RegisterClipboardFormatW")
	procGetClipboardSeqNum = user32.NewProc("GetClipboardSequenceNumber")
	procGlobalAlloc        = kernel32.NewProc("GlobalAlloc")
	procGlobalFree         = kernel32.NewProc("GlobalFree")
	procGlobalLock         = kernel32.NewProc("GlobalLock")
	procGlobalUnlock       = kernel32.NewProc("GlobalUnlock")
	procRtlMoveMemory      = kernel32.NewProc("RtlMoveMemory")
)

const (
	cfUnicodeText = 13
	gmemMoveable  = 0x0002
)

var (
	clipMu sync.Mutex
	ourSeq uint32
)

func openClipboardRetry(hwnd uintptr) error {
	for i := 0; i < 10; i++ {
		if r, _, _ := procOpenClipboard.Call(hwnd); r != 0 {
			return nil
		}
		time.Sleep(15 * time.Millisecond)
	}
	return errors.New("буфер обмена занят другим процессом")
}

func utf16FromBytes(b []byte) []uint16 {
	out := make([]uint16, 0, len(b)+1)
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		b = b[size:]
		if r == 0 {
			continue
		}
		out = utf16.AppendRune(out, r)
	}
	return append(out, 0)
}

func wipeU16(u []uint16) {
	for i := range u {
		u[i] = 0
	}
}

func hglobalFromU16(u []uint16) (uintptr, error) {
	byteLen := uintptr(len(u) * 2)
	h, _, _ := procGlobalAlloc.Call(gmemMoveable, byteLen)
	if h == 0 {
		return 0, errors.New("GlobalAlloc не удался")
	}
	p, _, _ := procGlobalLock.Call(h)
	if p == 0 {
		procGlobalFree.Call(h)
		return 0, errors.New("GlobalLock не удался")
	}
	procRtlMoveMemory.Call(p, uintptr(unsafe.Pointer(&u[0])), byteLen)
	procGlobalUnlock.Call(h)
	return h, nil
}

func setDwordFormat(name string, val uint32) error {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	fmtID, _, _ := procRegisterClipFormat.Call(uintptr(unsafe.Pointer(namePtr)))
	if fmtID == 0 {
		return fmt.Errorf("RegisterClipboardFormat(%s) не удался", name)
	}
	h, _, _ := procGlobalAlloc.Call(gmemMoveable, 4)
	if h == 0 {
		return errors.New("GlobalAlloc не удался")
	}
	p, _, _ := procGlobalLock.Call(h)
	if p == 0 {
		procGlobalFree.Call(h)
		return errors.New("GlobalLock не удался")
	}
	procRtlMoveMemory.Call(p, uintptr(unsafe.Pointer(&val)), 4)
	procGlobalUnlock.Call(h)
	if r, _, _ := procSetClipboardData.Call(fmtID, h); r == 0 {
		procGlobalFree.Call(h)
		return fmt.Errorf("SetClipboardData(%s) не удался", name)
	}
	return nil
}

func CopySensitive(hwnd uintptr, data []byte, ttl time.Duration) (warning string, err error) {
	if hwnd == 0 {
		return "", errors.New("окно для буфера обмена недоступно")
	}
	clipMu.Lock()
	defer clipMu.Unlock()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	u := utf16FromBytes(data)
	defer wipeU16(u)

	if err := openClipboardRetry(hwnd); err != nil {
		return "", err
	}
	defer procCloseClipboard.Call()

	if r, _, _ := procEmptyClipboard.Call(); r == 0 {
		return "", errors.New("EmptyClipboard не удался")
	}
	histErr := setDwordFormat("CanIncludeInClipboardHistory", 0)
	cloudErr := setDwordFormat("CanUploadToCloudClipboard", 0)
	_ = setDwordFormat("ExcludeClipboardContentFromMonitorProcessing", 0)
	if histErr != nil || cloudErr != nil {
		return "", errors.New("не удалось запретить историю/облако; пароль не скопирован")
	}
	h, err := hglobalFromU16(u)
	if err != nil {
		return "", err
	}
	if r, _, _ := procSetClipboardData.Call(cfUnicodeText, h); r == 0 {
		p, _, _ := procGlobalLock.Call(h)
		if p != 0 {
			wipeU16(u)
			procRtlMoveMemory.Call(p, uintptr(unsafe.Pointer(&u[0])), uintptr(len(u)*2))
			procGlobalUnlock.Call(h)
		}
		procGlobalFree.Call(h)
		return "", errors.New("SetClipboardData не удался")
	}

	seq, _, _ := procGetClipboardSeqNum.Call()
	ourSeq = uint32(seq)

	go func(mySeq uint32) {
		time.Sleep(ttl)
		retryClear(mySeq)
	}(ourSeq)
	return warning, nil
}

var clipOpen = openClipboardRetry
var clipClose = func() { procCloseClipboard.Call() }
var clipSequence = func() uint32 { seq, _, _ := procGetClipboardSeqNum.Call(); return uint32(seq) }
var clipEmpty = func() error {
	if r, _, _ := procEmptyClipboard.Call(); r == 0 {
		return errors.New("не удалось очистить буфер обмена")
	}
	return nil
}

func clearIfSeq(mySeq uint32) error {
	clipMu.Lock()
	defer clipMu.Unlock()
	if mySeq == 0 || ourSeq != mySeq {
		return nil
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := clipOpen(0); err != nil {
		return err
	}
	defer clipClose()
	if clipSequence() != mySeq {
		ourSeq = 0
		return nil
	}
	if err := clipEmpty(); err != nil {
		return err
	}
	ourSeq = 0
	return nil
}

func retryClear(mySeq uint32) {
	for clearIfSeq(mySeq) != nil {
		time.Sleep(250 * time.Millisecond)
	}
}

func ClearClipboardIfOwned() error {
	clipMu.Lock()
	mySeq := ourSeq
	clipMu.Unlock()
	if err := clearIfSeq(mySeq); err != nil {
		go retryClear(mySeq)
		return err
	}
	return nil
}

func WaitForClipboardClear() {
	clipMu.Lock()
	mySeq := ourSeq
	clipMu.Unlock()
	retryClear(mySeq)
}
