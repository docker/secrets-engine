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

package flock

import (
	"errors"
	"os"
	"time"
)

var errRecoverLock = errors.New("recovery failed. lock file is not older than 30 seconds")

// recoverStaleLock attempts to clear a stale lock file.
//
// A lock is considered stale if:
//   - the process that created it failed to remove the file, and
//   - the file’s modification time is at least 30 seconds old.
//
// On Unix systems, the stale lock file is deleted to allow recovery.
// This is not possible on Windows, since locked files cannot be removed.
//
// The file is always closed before the function returns, regardless of
// whether recovery succeeds.
//
// It returns nil if the lock file was successfully removed, or
// [errRecoverLock] if the lock was not considered stale.
func recoverStaleLock(root *os.Root, fl *os.File) error {
	defer func() { _ = fl.Close() }()

	info, err := fl.Stat()
	if err != nil {
		return err
	}

	// the lock file should not have existed for such a long time
	// it is possible that the application might have crashed before
	// let's try recover from that so that we don't lock indefinitely.
	if time.Since(info.ModTime()).Seconds() >= 30 {
		if err := root.Remove(lockFileName); err != nil {
			return err
		}
		return nil
	}
	return errRecoverLock
}
