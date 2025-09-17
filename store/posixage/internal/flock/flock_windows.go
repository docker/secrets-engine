//go:build windows

package flock

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

const (
	maxBytes = ^uint32(0) // lock the whole file
)

func lockFile(fd uintptr, exclusive bool) error {
	var flag uint32 = windows.LOCKFILE_FAIL_IMMEDIATELY
	if exclusive {
		flag |= windows.LOCKFILE_EXCLUSIVE_LOCK
	}
	var ov windows.Overlapped // zero offset => start at 0
	h := windows.Handle(fd)
	err := windows.LockFileEx(h, flag, 0, maxBytes, maxBytes, &ov)
	if err != nil {
		return err
	}
	return nil
}

// unlockFile releases an advisory lock held on the given file using UnlockFileEx.
//
// The file is always closed before the function returns.
func unlockFile(f *os.File) error {
	defer func() { _ = f.Close() }()

	var ov windows.Overlapped // zero offset => start at 0
	h := windows.Handle(f.Fd())
	err := windows.UnlockFileEx(h, 0, maxBytes, maxBytes, &ov)
	if err != nil {
		return errors.Join(ErrUnlockUnsuccessful, err)
	}
	return nil
}
