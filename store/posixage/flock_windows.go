//go:build windows

package posixage

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/cenkalti/backoff/v5"
	"golang.org/x/sys/windows"
)

const (
	maxBytes = ^uint32(0) // lock the whole file
)

// tryLockFile attempts to acquire an advisory lock on the provided file
// using LockFileEx.
//
// The function retries until the context is canceled, backing off
// exponentially between attempts up to a maximum delay of 100ms.
//
// Use the exclusive flag for write or delete operations to block concurrent
// readers.
func tryLockFile(ctx context.Context, f *os.File, exclusive bool) error {
	var flag uint32 = windows.LOCKFILE_FAIL_IMMEDIATELY
	if exclusive {
		flag |= windows.LOCKFILE_EXCLUSIVE_LOCK
	}

	var ov windows.Overlapped // zero offset => start at 0
	h := windows.Handle(f.Fd())

	ep := backoff.NewExponentialBackOff()
	ep.InitialInterval = time.Millisecond * 10
	ep.MaxInterval = time.Millisecond * 100
	_, err := backoff.Retry(ctx, func() (bool, error) {
		err := windows.LockFileEx(h, flag, 0, maxBytes, maxBytes, &ov)
		if err != nil {
			return false, errors.Join(ErrLockUnsuccessful, err)
		}
		return true, nil
	}, backoff.WithBackOff(ep))
	if err != nil {
		return errors.Join(ErrLockUnsuccessful, err)
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
