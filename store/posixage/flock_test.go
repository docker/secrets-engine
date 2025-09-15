package posixage

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFlock(t *testing.T) {
	t.Run("can unlock", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		require.NoError(t, err)

		exclusive := true
		unlock, err := attemptLock(root, exclusive, time.Millisecond*10)
		require.NoError(t, err)
		require.NoError(t, unlock())

		unlock, err = attemptLock(root, exclusive, time.Millisecond)
		require.NoError(t, err)
		require.NoError(t, unlock())
	})
	t.Run("exclusive lock prevents others from acquiring lock", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		require.NoError(t, err)

		exclusive := true
		unlock, err := attemptLock(root, exclusive, time.Millisecond)
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = unlock()
		})

		_, err = attemptLock(root, exclusive, time.Millisecond)
		require.ErrorIs(t, err, ErrLockUnsuccessful)

		_, err = attemptLock(root, !exclusive, time.Millisecond)
		require.ErrorIs(t, err, ErrLockUnsuccessful)
	})

	t.Run("multiple non-exclusive locks can be held", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		require.NoError(t, err)

		exclusive := true
		unlock, err := attemptLock(root, !exclusive, time.Millisecond)
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = unlock()
		})

		unlockTwo, err := attemptLock(root, !exclusive, time.Millisecond)
		require.NoError(t, err, ErrLockUnsuccessful)
		t.Cleanup(func() {
			_ = unlockTwo()
		})

		_, err = attemptLock(root, exclusive, time.Millisecond)
		require.ErrorIs(t, err, ErrLockUnsuccessful)
	})

	t.Run("can recover from an exclusive lock", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		require.NoError(t, err)

		exclusive := true
		_, err = attemptLock(root, exclusive, time.Millisecond)
		require.NoError(t, err)

		// change the lock file modification time
		fakeModTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		require.NoError(t, root.Chtimes(lockFileName, fakeModTime, fakeModTime))

		unlock, err := attemptLock(root, exclusive, time.Millisecond)
		require.NoError(t, err)
		require.NoError(t, unlock())
	})

	t.Run("recoverLock errors if a recover was not possible", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		require.NoError(t, err)

		f, err := root.Create(lockFileName)
		require.NoError(t, err)

		require.ErrorIs(t, recoverLock(root, f), errRecoverLock)
	})

	t.Run("recoverLock removes the file if it is older than 30 seconds", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		require.NoError(t, err)

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
