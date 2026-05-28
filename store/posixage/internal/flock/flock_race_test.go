// Copyright 2026 Docker, Inc.
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
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFlockRaces collects tests that exercise concurrency edge cases in
// the flock package. Each subtest documents the specific race it covers.
func TestFlockRaces(t *testing.T) {
	// isCurrentLockFile must report that the locked descriptor no longer
	// refers to the file at the lock-file path once the file has been
	// unlinked. This is the building block that prevents [acquireOnce]
	// from handing out a "ghost" lock on an inode that has been unlinked
	// by a concurrent stale-recovery.
	t.Run("isCurrentLockFile detects an unlinked path", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, root.Close()) })

		fl, err := openFile(root)
		require.NoError(t, err)
		t.Cleanup(func() { _ = fl.Close() })

		same, err := isCurrentLockFile(fl, root)
		require.NoError(t, err)
		assert.True(t, same, "fd and path should resolve to the same inode immediately after open")

		require.NoError(t, root.Remove(lockFileName))

		same, err = isCurrentLockFile(fl, root)
		require.NoError(t, err)
		assert.False(t, same, "fd should no longer match the path after the file is unlinked")
	})

	// isCurrentLockFile must also detect inode replacement: another caller
	// can unlink and immediately recreate the lock file via [openFile],
	// leaving us holding an fd to the orphaned inode while the path
	// resolves to a different inode.
	t.Run("isCurrentLockFile detects inode replacement", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, root.Close()) })

		flOld, err := openFile(root)
		require.NoError(t, err)
		t.Cleanup(func() { _ = flOld.Close() })

		require.NoError(t, root.Remove(lockFileName))
		flNew, err := openFile(root)
		require.NoError(t, err)
		t.Cleanup(func() { _ = flNew.Close() })

		same, err := isCurrentLockFile(flOld, root)
		require.NoError(t, err)
		assert.False(t, same, "old fd is on the unlinked inode; path now points to a new inode")

		same, err = isCurrentLockFile(flNew, root)
		require.NoError(t, err)
		assert.True(t, same, "newly opened fd should match the current path")
	})

	// recoverStaleLock is invoked from concurrent tryLock callers. Both
	// can read a stale modtime and race to unlink the file. The loser
	// of the race sees ENOENT from Remove; treating that as a hard error
	// would cause the outer tryLock to fail even though recovery
	// succeeded. The function must tolerate the concurrent unlink and
	// return nil for both callers.
	t.Run("concurrent recoverStaleLock both return success", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, root.Close()) })

		fl, err := openFile(root)
		require.NoError(t, err)
		require.NoError(t, fl.Close())
		stale := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		require.NoError(t, root.Chtimes(lockFileName, stale, stale))

		var (
			wg   sync.WaitGroup
			errs [2]error
		)
		wg.Add(2)
		for i := range 2 {
			go func() {
				defer wg.Done()
				errs[i] = recoverStaleLock(root)
			}()
		}
		wg.Wait()

		for i, e := range errs {
			assert.NoErrorf(t, e, "goroutine %d returned unexpected error from recoverStaleLock", i)
		}
	})

	// The heartbeat goroutine started by [tryLock] must keep the lock
	// file's modtime young enough that concurrent recovery callers see
	// the lock as live. Without the heartbeat, a holder doing work
	// longer than [staleThreshold] is hijacked: another process unlinks
	// the file and creates a fresh inode at the same path. This test
	// shortens both intervals so we can observe the protection in
	// well under the production 30s window.
	t.Run("heartbeat keeps a long-running holder live for recovery", func(t *testing.T) {
		origHB, origStale := heartbeatInterval, staleThreshold
		heartbeatInterval = 20 * time.Millisecond
		staleThreshold = 100 * time.Millisecond
		t.Cleanup(func() {
			heartbeatInterval = origHB
			staleThreshold = origStale
		})

		root, err := os.OpenRoot(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, root.Close()) })

		unlock, err := tryLock(t.Context(), root, true)
		require.NoError(t, err)
		t.Cleanup(func() { _ = unlock() })

		// Sleep well past staleThreshold; heartbeat should be firing
		// every 20ms so the file's modtime should keep refreshing.
		time.Sleep(5 * staleThreshold)

		assert.ErrorIs(t, recoverStaleLock(root), errRecoverLock,
			"recoverStaleLock should refuse to recover a heartbeating lock")
	})
}
