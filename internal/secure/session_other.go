//go:build !windows

package secure

func SessionUnavailable(_ uintptr) bool { return false }
