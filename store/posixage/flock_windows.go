//go:build windows

package posixage

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
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
	flag := windows.LOCKFILE_FAIL_IMMEDIATELY
	if exclusive {
		flag |= windows.LOCKFILE_EXCLUSIVE_LOCK
	}

	var overlapped windows.Overlapped
	err := windows.LockFileEx(windows.Handle(f.Fd()), uint32(flag), 0, 1, 0, &overlapped)
	if err != nil {
		return nil, errors.Join(ErrLockUnsuccessful, err)
	}

	return func() error {
		defer func() { _ = f.Close() }()
		var overlapped windows.Overlapped
		err := windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &overlapped)
		if err != nil {
			return errors.Join(ErrUnlockUnsuccessful, err)
		}
		return nil
	}, nil
}
