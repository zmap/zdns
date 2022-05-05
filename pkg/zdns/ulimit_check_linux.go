//go:build linux || darwin
// +build linux darwin

package zdns

import (
	"syscall"

	log "github.com/sirupsen/logrus"
)

func ulimit_check(max_open_files uint64) {
	var rLimit syscall.Rlimit
	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		log.Fatal("Failed to fetch ulimit ", err)
	}

	if max_open_files > rLimit.Cur {
		log.Warn("Current nofile limit (", rLimit.Cur, ") lower than maximum connection count (", max_open_files, "), try to update.")

		rLimit.Max = max_open_files
		rLimit.Cur = max_open_files
		err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
		if err != nil {
			log.Fatal("Error setting nofile limit to ", rLimit.Cur, ": ", err)
		}
		log.Info("Updated nofile limit to ", rLimit.Cur)
	}
}
