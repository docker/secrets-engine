//go:build windows

package posixage

import (
	"errors"
	"os"
	"sync"

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
	var flag uint32 = windows.LOCKFILE_FAIL_IMMEDIATELY
	if exclusive {
		flag |= windows.LOCKFILE_EXCLUSIVE_LOCK
	}

	var ov windows.Overlapped   // zero offset => start at 0
	const maxBytes = ^uint32(0) // lock the whole file
	h := windows.Handle(f.Fd())

	err := windows.LockFileEx(h, flag, 0, maxBytes, maxBytes, &ov)
	if err != nil {
		return nil, errors.Join(ErrLockUnsuccessful, err)
	}

	return sync.OnceValue(func() error {
		defer func() { _ = f.Close() }()
		err := windows.UnlockFileEx(h, 0, maxBytes, maxBytes, &ov)
		if err != nil {
			return errors.Join(ErrUnlockUnsuccessful, err)
		}
		return nil
	}), nil
}
