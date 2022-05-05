//go:build !linux && !darwin
// +build !linux,!darwin

package zdns

func ulimit_check(max_open_files uint64) {
	// fallback for ulimit check on unsupported platform
}
