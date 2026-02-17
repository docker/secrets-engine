// Copyright 2025-2026 Docker, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !windows

package flock

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func lockFile(fd uintptr, exclusive bool) error {
	flag := unix.LOCK_NB
	if exclusive {
		flag |= unix.LOCK_EX
	} else {
		flag |= unix.LOCK_SH
	}
	return unix.Flock(int(fd), flag)
}

// unlockFile releases an advisory lock held on the given file using flock.
//
// The file is always closed before the function returns.
func unlockFile(f *os.File) error {
	defer func() { _ = f.Close() }()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_UN); err != nil {
		return errors.Join(ErrUnlockUnsuccessful, err)
	}
	return nil
}
