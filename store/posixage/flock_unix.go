//go:build !windows

package posixage

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func lockFile(root *os.Root, exclusive bool) (unlockFunc, error) {
	fl, err := openFile(root)
	if err != nil {
		return nil, err
	}

	flag := unix.LOCK_NB
	if exclusive {
		flag |= unix.LOCK_EX
	} else {
		flag |= unix.LOCK_SH
	}
	err = unix.Flock(int(fl.Fd()), flag)
	if err != nil {
		_ = fl.Close()
		return nil, errors.Join(ErrLockUnsuccessful, err)
	}

	return func() error {
		if err := fl.Close(); err != nil {
			return err
		}
		if err := unix.Flock(int(fl.Fd()), unix.LOCK_UN); err != nil {
			return errors.Join(ErrUnlockUnsuccessful, err)
		}
		return nil
	}, nil
}
