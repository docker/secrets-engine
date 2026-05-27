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
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// rawFlockExclusive opens the lock file directly and acquires a non-blocking
// exclusive flock on a brand-new open file description. It returns the file
// handle so the caller can hold the lock independently of the package APIs.
//
// This mirrors the cross-process behavior: each open() yields a separate
// open file description, so the kernel treats two such handles as
// independent lock holders even within the same process.
func rawFlockExclusive(t *testing.T, root *os.Root) *os.File {
	t.Helper()
	f, err := root.OpenFile(lockFileName, os.O_RDWR|os.O_CREATE, 0o600)
	require.NoError(t, err)
	require.NoError(t, unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB))
	return f
}

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

	// Two waiters racing to acquire after a stale holder must end with at
	// most one caller holding the lock. Inode verification makes sure
	// that even if both callers' recovery paths interleave with their
	// retries, only one walks away believing they own the lock.
	t.Run("two waiters cannot both acquire after recovery", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, root.Close()) })

		holderFile := rawFlockExclusive(t, root)
		t.Cleanup(func() {
			_ = unix.Flock(int(holderFile.Fd()), unix.LOCK_UN)
			_ = holderFile.Close()
		})
		stale := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		require.NoError(t, root.Chtimes(lockFileName, stale, stale))

		var (
			wg       sync.WaitGroup
			unlocks  [2]UnlockFunc
			lockErrs [2]error
		)
		wg.Add(2)
		for i := range 2 {
			go func() {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
				defer cancel()
				unlocks[i], lockErrs[i] = tryLock(ctx, root, true)
			}()
		}
		wg.Wait()

		t.Cleanup(func() {
			for _, u := range unlocks {
				if u != nil {
					_ = u()
				}
			}
		})

		successes := 0
		for _, e := range lockErrs {
			if e == nil {
				successes++
			}
		}
		assert.LessOrEqualf(t, successes, 1,
			"%d callers acquired the lock concurrently; recovery handed it out more than once",
			successes)
	})

	// The 30s threshold is checked against the lock file's modification
	// time, which is only refreshed at acquisition. A holder that takes
	// longer than 30s to complete its work has no way to signal liveness
	// to other processes — its lock file looks stale to anyone who
	// queries it. This test documents that limitation; closing it
	// requires a periodic modtime refresh (background heartbeat) while
	// the lock is held.
	t.Run("long-running holder still has no liveness signal", func(t *testing.T) {
		t.Skip("known limitation: inode verification does not protect a holder " +
			"whose modtime ages past 30s. A background heartbeat that re-truncates " +
			"the lock file would be required to fully fix this race.")
	})

	// This is the original cross-process hijack scenario. A live holder
	// has flock on inode A; another caller, seeing the modtime stale,
	// unlinks the file and creates a fresh inode B. The new caller
	// passes inode verification because its fd and the path both point
	// to B — but the original holder's flock on A is still live.
	//
	// Inode verification alone cannot close this race because the
	// hijacked holder never re-checks. A complete fix requires the
	// holder to periodically verify its locked inode is still at the
	// path, or to refresh the modtime to keep recovery from firing.
	t.Run("stale recovery can still hijack a long-running holder", func(t *testing.T) {
		t.Skip("known limitation: inode verification only protects the side that " +
			"is *acquiring* the lock. A holder whose modtime is allowed to age past " +
			"30s can still be hijacked because the holder never re-verifies. Pair " +
			"this fix with a heartbeat or a holder-side re-check to close fully.")
	})
}
