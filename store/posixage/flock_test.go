package posixage

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFlock(t *testing.T) {
	t.Run("exclusive lock prevents others from acquiring lock", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		require.NoError(t, err)

		exclusive := true
		unlock, err := lockFile(root, exclusive)
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = unlock()
		})

		_, err = lockFile(root, exclusive)
		require.ErrorIs(t, err, ErrLockUnsuccessful)

		_, err = lockFile(root, !exclusive)
		require.ErrorIs(t, err, ErrLockUnsuccessful)
	})

	t.Run("multiple non-exclusive locks can be held", func(t *testing.T) {
		root, err := os.OpenRoot(t.TempDir())
		require.NoError(t, err)

		exclusive := true
		unlock, err := lockFile(root, !exclusive)
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = unlock()
		})

		unlockTwo, err := lockFile(root, !exclusive)
		require.NoError(t, err, ErrLockUnsuccessful)
		t.Cleanup(func() {
			_ = unlockTwo()
		})

		_, err = lockFile(root, exclusive)
		require.ErrorIs(t, err, ErrLockUnsuccessful)
	})
}
