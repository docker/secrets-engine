//go:build !windows

package flock

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func lockFile(fd uintptr, exclusive bool) error {
	flag := unix.LOCK_NB
	if exclusive {
		flag |= unix.LOCK_EX
	} else {
		flag |= unix.LOCK_SH
	}
	return unix.Flock(int(fd), flag)
}

// unlockFile releases an advisory lock held on the given file using flock.
//
// The file is always closed before the function returns.
func unlockFile(f *os.File) error {
	defer func() { _ = f.Close() }()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_UN); err != nil {
		return errors.Join(ErrUnlockUnsuccessful, err)
	}
	return nil
}
