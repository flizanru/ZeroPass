//go:build windows

package secure

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	semFailCriticalErrors = 0x0001
	semNoGPFaultErrorBox  = 0x0002
	semNoOpenFileErrorBox = 0x8000
	deviceNotifyCallback  = 2
	pbtAPMSuspend         = 0x0004

	// PROCESS_MITIGATION_POLICY values from Windows SDK 10.0.22621 winnt.h.
	processDynamicCodePolicy           = 2
	processStrictHandleCheckPolicy     = 3
	processExtensionPointDisablePolicy = 6
	processSignaturePolicy             = 8
	processImageLoadPolicy             = 10
)

const selfProcessUserRights windows.ACCESS_MASK = windows.PROCESS_QUERY_LIMITED_INFORMATION | windows.PROCESS_TERMINATE | windows.SYNCHRONIZE | windows.READ_CONTROL
const selfProcessSystemRights windows.ACCESS_MASK = windows.PROCESS_ALL_ACCESS | windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE

var (
	powrprof                                     = windows.NewLazySystemDLL("powrprof.dll")
	procPowerRegisterSuspendResumeNotification   = powrprof.NewProc("PowerRegisterSuspendResumeNotification")
	procPowerUnregisterSuspendResumeNotification = powrprof.NewProc("PowerUnregisterSuspendResumeNotification")
	procSetProcessMitigationPolicy               = kernel32.NewProc("SetProcessMitigationPolicy")
	strictHandlesEnabled                         atomic.Bool
)

type deviceNotifySubscribeParameters struct {
	Callback uintptr
	Context  uintptr
}

func SuppressCrashDumps() {
	windows.SetErrorMode(semFailCriticalErrors | semNoGPFaultErrorBox | semNoOpenFileErrorBox)
}

func SetStrictHandles(enabled bool) { strictHandlesEnabled.Store(enabled) }

func setMitigation(policy uintptr, flags uint32) error {
	r, _, callErr := procSetProcessMitigationPolicy.Call(
		policy,
		uintptr(unsafe.Pointer(&flags)),
		unsafe.Sizeof(flags),
	)
	if r == 0 {
		return callErr
	}
	return nil
}

// ApplyMitigations is fail-soft: every supported policy is attempted and all
// failures are returned to the UI. Bit layouts match the DWORD unions in
// winnt.h: extension=bit 0; image load=bits 0..2; strict handles=bits 0..1.
func ApplyMitigations() []error {
	var failures []error
	if err := setMitigation(processExtensionPointDisablePolicy, 1<<0); err != nil {
		failures = append(failures, fmt.Errorf("ProcessExtensionPointDisablePolicy: %w", err))
	}
	if err := setMitigation(processImageLoadPolicy, 1<<0|1<<1|1<<2); err != nil {
		failures = append(failures, fmt.Errorf("ProcessImageLoadPolicy: %w", err))
	}
	if strictHandlesEnabled.Load() {
		if err := setMitigation(processStrictHandleCheckPolicy, 1<<0|1<<1); err != nil {
			failures = append(failures, fmt.Errorf("ProcessStrictHandleCheckPolicy: %w", err))
		}
	}
	return failures
}

// DenySelfProcessAccess blocks unprivileged processes running as the current
// user from VM read/write, remote-thread, handle-duplication and process-setting
// rights. An administrator with SeDebugPrivilege can bypass this DACL.
func DenySelfProcessAccess() error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	var pinner runtime.Pinner
	defer pinner.Unpin()
	pinner.Pin(user.User.Sid)
	pinner.Pin(system)
	entries := []windows.EXPLICIT_ACCESS{
		{
			AccessPermissions: selfProcessUserRights,
			AccessMode:        windows.GRANT_ACCESS,
			Trustee: windows.TRUSTEE{
				TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(user.User.Sid),
			},
		},
		{
			AccessPermissions: selfProcessSystemRights,
			AccessMode:        windows.GRANT_ACCESS,
			Trustee: windows.TRUSTEE{
				TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(system),
			},
		},
	}
	dacl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(
		windows.CurrentProcess(), windows.SE_KERNEL_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	)
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
