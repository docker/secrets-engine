//go:build !windows

package posixage

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/cenkalti/backoff/v5"
	"golang.org/x/sys/unix"
)

// tryLockFile attempts to acquire an advisory lock on the provided file
// using flock.
//
// The function retries until the context is canceled, backing off
// exponentially between attempts up to a maximum delay of 100ms.
//
// Use the exclusive flag for write or delete operations to block concurrent
// readers.
func tryLockFile(ctx context.Context, f *os.File, exclusive bool) error {
	flag := unix.LOCK_NB
	if exclusive {
		flag |= unix.LOCK_EX
	} else {
		flag |= unix.LOCK_SH
	}

	ep := backoff.NewExponentialBackOff()
	ep.InitialInterval = time.Millisecond * 10
	ep.MaxInterval = time.Millisecond * 100
	_, err := backoff.Retry(ctx, func() (bool, error) {
		if err := unix.Flock(int(f.Fd()), flag); err != nil {
			return false, err
		}
		return true, nil
	}, backoff.WithBackOff(ep))
	if err != nil {
		return errors.Join(ErrLockUnsuccessful, err)
	}

	return nil
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
