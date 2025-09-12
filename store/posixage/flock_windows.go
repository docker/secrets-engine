//go:build windows

package posixage

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func lockFile(root *os.Root, exclusive bool) (unlockFunc, error) {
	fl, err := openFile(root)
	if err != nil {
		return nil, err
	}

	flag := windows.LOCKFILE_FAIL_IMMEDIATELY
	if exclusive {
		flag |= windows.LOCKFILE_EXCLUSIVE_LOCK
	}
	var overlapped windows.Overlapped
	err = windows.LockFileEx(windows.Handle(fl.Fd()), uint32(flag), 0, 1, 0, &overlapped)
	if err != nil {
		return nil, errors.Join(ErrLockUnsuccessful, err)
	}
	return func() error {
		if err := fl.Close(); err != nil {
			return err
		}
		var overlapped windows.Overlapped
		err := windows.UnlockFileEx(windows.Handle(fl.Fd()), 0, 1, 0, &overlapped)
		if err != nil {
			return errors.Join(ErrUnlockUnsuccessful, err)
		}
		return nil
	}, nil
}
