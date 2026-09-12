//go:build windows

package secure

import (
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	semFailCriticalErrors = 0x0001
	semNoGPFaultErrorBox  = 0x0002
	semNoOpenFileErrorBox = 0x8000
	deviceNotifyCallback  = 2
	pbtAPMSuspend         = 0x0004
)

var (
	powrprof                                     = windows.NewLazySystemDLL("powrprof.dll")
	procPowerRegisterSuspendResumeNotification   = powrprof.NewProc("PowerRegisterSuspendResumeNotification")
	procPowerUnregisterSuspendResumeNotification = powrprof.NewProc("PowerUnregisterSuspendResumeNotification")
)

type deviceNotifySubscribeParameters struct {
	Callback uintptr
	Context  uintptr
}

func SuppressCrashDumps() {
	windows.SetErrorMode(semFailCriticalErrors | semNoGPFaultErrorBox | semNoOpenFileErrorBox)
}

// LockOnSuspend registers a callback that only queues a notification. Windows
// invokes it on an arbitrary OS thread, so the callback must not touch GUI state.
func LockOnSuspend(onSuspend func()) (release func(), err error) {
	callback := windows.NewCallback(func(_, eventType, _ uintptr) uintptr {
		if eventType == pbtAPMSuspend {
			onSuspend()
		}
		return 0
	})
	params := deviceNotifySubscribeParameters{Callback: callback}
	var handle uintptr
	status, _, _ := procPowerRegisterSuspendResumeNotification.Call(
		deviceNotifyCallback,
		uintptr(unsafe.Pointer(&params)),
		uintptr(unsafe.Pointer(&handle)),
	)
	if status != 0 {
		return func() {}, fmt.Errorf("регистрация уведомлений сна Windows: %w", windows.Errno(status))
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			procPowerUnregisterSuspendResumeNotification.Call(handle)
			runtime.KeepAlive(callback)
		})
	}, nil
}
