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

package flock

import (
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFlock(t *testing.T) {
	t.Run("can unlock", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() {
			assert.NoError(t, root.Close())
		})

		exclusive := true
		unlock, err := tryLock(t.Context(), root, exclusive)
		require.NoError(t, err)
		require.NoError(t, unlock())

		unlock, err = tryLock(t.Context(), root, exclusive)
		require.NoError(t, err)
		require.NoError(t, unlock())
	})
	t.Run("exclusive lock prevents others from acquiring lock", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() {
			assert.NoError(t, root.Close())
		})

		exclusive := true
		unlock, err := tryLock(t.Context(), root, exclusive)
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = unlock()
		})

		_, err = tryLock(t.Context(), root, exclusive)
		require.ErrorIs(t, err, ErrLockUnsuccessful)

		_, err = tryLock(t.Context(), root, !exclusive)
		require.ErrorIs(t, err, ErrLockUnsuccessful)
	})

	t.Run("multiple non-exclusive locks can be held", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() {
			assert.NoError(t, root.Close())
		})

		exclusive := true
		unlock, err := tryLock(t.Context(), root, !exclusive)
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = unlock()
		})

		unlockTwo, err := tryLock(t.Context(), root, !exclusive)
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = unlockTwo()
		})

		_, err = tryLock(t.Context(), root, exclusive)
		require.ErrorIs(t, err, ErrLockUnsuccessful)
	})

	t.Run("can recover from an exclusive lock", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("recovery from an exclusive lock is not supported on Windows yet")
		}
		root, err := os.OpenRoot(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() {
			assert.NoError(t, root.Close())
		})

		exclusive := true
		_, err = tryLock(t.Context(), root, exclusive)
		require.NoError(t, err)

		// change the lock file modification time
		fakeModTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		require.NoError(t, root.Chtimes(lockFileName, fakeModTime, fakeModTime))

		unlock, err := tryLock(t.Context(), root, exclusive)
		require.NoError(t, err)
		require.NoError(t, unlock())
	})
}

func TestRecoverLock(t *testing.T) {
	t.Run("recoverLock does not recover if the lock is newer than 30s", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() {
			assert.NoError(t, root.Close())
		})

		f, err := root.Create(lockFileName)
		require.NoError(t, err)

		require.ErrorIs(t, recoverStaleLock(root, f), errRecoverLock)
	})

	t.Run("recoverLock removes the file if it is older than 30 seconds", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() {
			assert.NoError(t, root.Close())
		})

		f, err := root.Create(lockFileName)
		require.NoError(t, err)
		// change the lock file modification time
		fakeModTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		require.NoError(t, root.Chtimes(lockFileName, fakeModTime, fakeModTime))

		require.NoError(t, recoverStaleLock(root, f))
		_, err = root.Stat(lockFileName)
		require.ErrorIs(t, err, os.ErrNotExist)
	})
}
