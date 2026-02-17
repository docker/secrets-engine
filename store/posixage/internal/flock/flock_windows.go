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

//go:build windows

package flock

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

const (
	maxBytes = ^uint32(0) // lock the whole file
)

func lockFile(fd uintptr, exclusive bool) error {
	var flag uint32 = windows.LOCKFILE_FAIL_IMMEDIATELY
	if exclusive {
		flag |= windows.LOCKFILE_EXCLUSIVE_LOCK
	}
	var ov windows.Overlapped // zero offset => start at 0
	h := windows.Handle(fd)
	err := windows.LockFileEx(h, flag, 0, maxBytes, maxBytes, &ov)
	if err != nil {
		return err
	}
	return nil
}

// unlockFile releases an advisory lock held on the given file using UnlockFileEx.
//
// The file is always closed before the function returns.
func unlockFile(f *os.File) error {
	defer func() { _ = f.Close() }()

	var ov windows.Overlapped // zero offset => start at 0
	h := windows.Handle(f.Fd())
	err := windows.UnlockFileEx(h, 0, maxBytes, maxBytes, &ov)
	if err != nil {
		return errors.Join(ErrUnlockUnsuccessful, err)
	}
	return nil
}
