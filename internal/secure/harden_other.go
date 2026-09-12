//go:build !windows

package secure

func SuppressCrashDumps() {}

func LockOnSuspend(_ func()) (func(), error) { return func() {}, nil }
