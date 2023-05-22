//go:build linux || darwin
// +build linux darwin

/*
 * ZDNS Copyright 2020 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */
package zdns

import (
	"syscall"

	log "github.com/sirupsen/logrus"
)

func ulimitCheck(maxOpenFiles uint64) {
	var rLimit syscall.Rlimit
	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		log.Fatal("Failed to fetch ulimit ", err)
	}

	if maxOpenFiles > rLimit.Cur {
		log.Warn("Current nofile limit (", rLimit.Cur, ") lower than maximum connection count (", maxOpenFiles, "), trying to update.")

		rLimit.Max = maxOpenFiles
		rLimit.Cur = maxOpenFiles
		err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
		if err != nil {
			log.Fatal("Error setting nofile limit to ", rLimit.Cur, ": ", err)
		}
		log.Info("Updated nofile limit to ", rLimit.Cur)
	}
}
