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
	"io/fs"
	"os"
	"time"
)

var errRecoverLock = errors.New("recovery failed. lock file is not older than 30 seconds")

// staleThreshold is the modtime age past which a lock file is considered
// abandoned. A holder refreshes the modtime at acquisition and again on
// every [heartbeatInterval] tick via [heartbeat], so a still-held lock
// will not be misidentified as stale unless the holder is genuinely
// stuck (no scheduler progress) for longer than this window.
//
// Exposed as a var rather than a const so tests can shorten it.
var staleThreshold = 30 * time.Second

// recoverStaleLock attempts to clear a stale lock file at the configured
// lock-file path.
//
// A lock is considered stale if its modification time is at least
// [staleThreshold] old. On Unix the stale lock file is unlinked; on
// Windows this typically fails while another process has the file open.
//
// The function tolerates concurrent removers: if the file disappears
// between the modtime check and the unlink, nil is returned. Callers
// using [acquireOnce] are still protected by the inode verification it
// performs after [lockFile], so a missed recovery cannot let two callers
// hold the same name.
//
// It returns nil when the lock file was removed (or already gone) and
// [errRecoverLock] when the lock was not considered stale.
func recoverStaleLock(root *os.Root) error {
	info, err := root.Stat(lockFileName)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// nothing to recover; subsequent open will create a fresh file
			return nil
		}
		return err
	}

	if time.Since(info.ModTime()) < staleThreshold {
		return errRecoverLock
	}

	if err := root.Remove(lockFileName); err != nil {
		// another caller raced us to the unlink — recovery still succeeded
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	return nil
}
