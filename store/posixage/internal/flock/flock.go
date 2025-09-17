package flock

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v5"
)

var (
	ErrLockUnsuccessful   = errors.New("store is locked")
	ErrUnlockUnsuccessful = errors.New("could not unlock store")
)

const (
	defaultLockTimeout = time.Millisecond * 100
	lockFileName       = ".posixage.lock"
)

// UnlockFunc is the callback function returned by [TryLock] and [TryRLock]
// it should always be called inside a defer.
type UnlockFunc func() error

// openFile is a helper function for internal use by [tryLock]
func openFile(root *os.Root) (*os.File, error) {
	// we need to open in readwrite mode so that the file modtime gets updated
	// with os.Truncate when we actually acquire a lock.
	fl, err := root.OpenFile(lockFileName, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}

	return fl, nil
}

func tryLock(ctx context.Context, root *os.Root, exclusive bool) (UnlockFunc, error) {
	var (
		err error
		fl  *os.File
	)

	defer func() {
		// we must always close the file on any error returned
		if err != nil && fl != nil {
			_ = fl.Close()
		}
	}()

	fl, err = openFile(root)
	if err != nil {
		return nil, err
	}

	err = retryLock(ctx, fl, exclusive)
	// lock was successful if error == nil, so let's just return
	if err == nil {
		return sync.OnceValue(func() error {
			return unlockFile(fl)
		}), nil
	}

	// lock was unsuccessful so let's retry
	if recoverErr := recoverStaleLock(root, fl); recoverErr != nil {
		// return on recovery failed.
		// perhaps the file is still locked and not older than 30 seconds?
		// maybe a permission error prevented it from being removed?
		return nil, errors.Join(err, recoverErr)
	}

	fl, err = openFile(root)
	if err != nil {
		return nil, err
	}
	// recovery was successful. Let's try get another lock one last time.
	if err := retryLock(ctx, fl, exclusive); err != nil {
		return nil, err
	}

	return sync.OnceValue(func() error {
		return unlockFile(fl)
	}), nil
}

// retryLock attempts to acquire an advisory lock on the given file
// using flock, retrying until [defaultLockTimeout] is reached
// or the context is canceled.
//
// Retries use exponential backoff with a maximum delay of 100ms
// between attempts.
//
// Set exclusive to true for write or delete operations to prevent
// concurrent reads.
func retryLock(ctx context.Context, f *os.File, exclusive bool) error {
	lockCtx, lockCtxCancel := context.WithTimeout(ctx, defaultLockTimeout)
	defer lockCtxCancel()

	ep := backoff.NewExponentialBackOff()
	ep.InitialInterval = time.Millisecond * 10
	ep.MaxInterval = time.Millisecond * 100
	_, err := backoff.Retry(lockCtx, func() (bool, error) {
		if err := lockFile(f.Fd(), exclusive); err != nil {
			return false, err
		}
		return true, nil
	}, backoff.WithBackOff(ep))
	if err != nil {
		return errors.Join(ErrLockUnsuccessful, err)
	}

	// truncate to update the modtime to signal to other processes that the
	// current lock is valid so they don't attempt a recovery on it.
	_ = f.Truncate(0)

	return nil
}

// TryLock acquires an exclusive advisory lock on a lock file.
//
// If the file does not exist, it is created. If the lock cannot be
// acquired immediately, the function retries until the default timeout
// (100ms) is reached.
//
// As a safeguard, the function attempts to recover from stale locks,
// defined as lock files older than 30 seconds. If recovery fails,
// manual intervention may be required.
//
// It returns an unlock function that must be called to release the lock.
func TryLock(ctx context.Context, root *os.Root) (UnlockFunc, error) {
	return tryLock(ctx, root, true)
}

// TryRLock acquires a non-exclusive advisory lock on a lock file.
//
// If the file does not exist, it is created. If the lock cannot be
// acquired immediately, the function retries until the default timeout
// (100ms) is reached.
//
// As a safeguard, the function attempts to recover from stale locks,
// defined as lock files older than 30 seconds. If recovery fails,
// manual intervention may be required.
//
// It returns an unlock function that must be called to release the lock.
func TryRLock(ctx context.Context, root *os.Root) (UnlockFunc, error) {
	return tryLock(ctx, root, false)
}
