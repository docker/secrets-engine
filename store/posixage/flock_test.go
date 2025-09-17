package posixage

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
		unlock, err := attemptLock(t.Context(), root, exclusive)
		require.NoError(t, err)
		require.NoError(t, unlock())

		unlock, err = attemptLock(t.Context(), root, exclusive)
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
		unlock, err := attemptLock(t.Context(), root, exclusive)
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = unlock()
		})

		_, err = attemptLock(t.Context(), root, exclusive)
		require.ErrorIs(t, err, ErrLockUnsuccessful)

		_, err = attemptLock(t.Context(), root, !exclusive)
		require.ErrorIs(t, err, ErrLockUnsuccessful)
	})

	t.Run("multiple non-exclusive locks can be held", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() {
			assert.NoError(t, root.Close())
		})

		exclusive := true
		unlock, err := attemptLock(t.Context(), root, !exclusive)
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = unlock()
		})

		unlockTwo, err := attemptLock(t.Context(), root, !exclusive)
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = unlockTwo()
		})

		_, err = attemptLock(t.Context(), root, exclusive)
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
		_, err = attemptLock(t.Context(), root, exclusive)
		require.NoError(t, err)

		// change the lock file modification time
		fakeModTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		require.NoError(t, root.Chtimes(lockFileName, fakeModTime, fakeModTime))

		unlock, err := attemptLock(t.Context(), root, exclusive)
		require.NoError(t, err)
		require.NoError(t, unlock())
	})
}

func TestRecoverLock(t *testing.T) {
	t.Run("recoverLock errors if a recover was not possible", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		require.NoError(t, err)
		t.Cleanup(func() {
			assert.NoError(t, root.Close())
		})

		f, err := root.Create(lockFileName)
		require.NoError(t, err)

		require.ErrorIs(t, recoverLock(root, f), errRecoverLock)
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

		require.NoError(t, recoverLock(root, f))
		_, err = root.Stat(lockFileName)
		require.ErrorIs(t, err, os.ErrNotExist)
	})
}
