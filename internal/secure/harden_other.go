//go:build !windows

package secure

func SuppressCrashDumps() {}

func SetStrictHandles(_ bool) {}

func ApplyMitigations() []error { return nil }

func DenySelfProcessAccess() error { return nil }

func LockOnSuspend(_ func()) (func(), error) { return func() {}, nil }
