//go:build !windows

package posixage

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// lockFile acquires a file-based lock using a temporary file.
//
// The exclusive flag should be set for write or delete operations to prevent
// concurrent reads. The timeout parameter defines how long to keep retrying
// before giving up.
//
// It returns an [unlockFunc] on success which should always be called inside
// a defer.
func lockFile(f *os.File, exclusive bool) (unlockFunc, error) {
	flag := unix.LOCK_NB
	if exclusive {
		flag |= unix.LOCK_EX
	} else {
		flag |= unix.LOCK_SH
	}

	err := unix.Flock(int(f.Fd()), flag)
	if err != nil {
		return nil, errors.Join(ErrLockUnsuccessful, err)
	}

	return func() error {
		defer func() { _ = f.Close() }()
		if err := unix.Flock(int(f.Fd()), unix.LOCK_UN); err != nil {
			return errors.Join(ErrUnlockUnsuccessful, err)
		}

		return nil
	}, nil
}
