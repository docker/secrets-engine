package posixage

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"
)

var (
	ErrLockUnsuccessful   = errors.New("store is locked")
	ErrUnlockUnsuccessful = errors.New("could not unlock store")
)

const lockFileName = ".posixage.lock"

// unlockFunc is the callback function returned by [attemptLock]
// it should always be called inside a defer.
type unlockFunc func() error

// openFile is a helper function for internal use by [attemptLock]
func openFile(root *os.Root) (*os.File, error) {
	// we need to open in readwrite mode so that the file modtime gets updated
	// with os.Truncate when we actually acquire a lock.
	fl, err := root.OpenFile(lockFileName, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}

	return fl, nil
}

// attemptLock acquires a file-based lock using a temporary file.
//
// If the lock file does not exist, it is created. If the lock cannot be
// acquired immediately, the function retries until the specified timeout
// is reached.
//
// To recover from stale locks (e.g., if a process crashes before releasing),
// the function removes the lock file if its modification time is older than
// 30 seconds. This assumes no valid process would hold the lock that long.
func attemptLock(ctx context.Context, root *os.Root, exclusive bool) (unlockFunc, error) {
	fl, err := openFile(root)
	if err != nil {
		return nil, err
	}

	lockCtx, lockCtxCancel := context.WithTimeout(ctx, time.Millisecond*100)
	defer lockCtxCancel()
	err = tryLockFile(lockCtx, fl, exclusive)
	// lock was successful if error == nil, so let's just return
	if err == nil {
		// truncate to update the modtime to signal to other processes that the
		// current lock is valid so they don't attempt a recovery on it.
		_ = fl.Truncate(0)

		return sync.OnceValue(func() error {
			return unlockFile(fl)
		}), nil
	}

	// lock was unsuccessful so let's retry
	if recoverErr := recoverLock(root, fl); recoverErr != nil {
		// return on recovery failed.
		// perhaps the file is still locked and not older than 30 seconds?
		// maybe a permission error prevented it from being removed?
		return nil, errors.Join(err, filterRecoverError(recoverErr))
	}

	fl, err = openFile(root)
	if err != nil {
		return nil, err
	}
	// recovery was successful. Let's try get another lock one last time.
	lockAgainCtx, lockAgainCtxCancel := context.WithTimeout(ctx, time.Millisecond*100)
	defer lockAgainCtxCancel()
	// try acquire a lock - immediately return on any error
	if err := tryLockFile(lockAgainCtx, fl, exclusive); err != nil {
		// always close the lock file after an error
		_ = fl.Close()
		return nil, err
	}
	// truncate to update the modtime to signal to other processes that the
	// current lock is valid so they don't attempt a recovery on it.
	_ = fl.Truncate(0)

	return sync.OnceValue(func() error {
		return unlockFile(fl)
	}), nil
}

func filterRecoverError(err error) error {
	if errors.Is(err, errRecoverLock) {
		return nil
	}
	return err
}

var errRecoverLock = errors.New("recovery failed. lock file is not older than 30 seconds")

// recoverLock checks whether a lock file's modification time is older than
// 30 seconds. If so, it removes the file to recover from a stale lock.
//
// The file is always closed, since this function is intended to be called
// as a last resort when acquiring a lock.
//
// It returns no error if the lock file was successfully removed.
func recoverLock(root *os.Root, fl *os.File) error {
	defer func() { _ = fl.Close() }()

	info, err := fl.Stat()
	if err != nil {
		return err
	}

	// the lock file should not have existed for such a long time
	// it is possible that the application might have crashed before
	// let's try recover from that so that we don't lock indefinitely.
	if time.Since(info.ModTime()).Seconds() >= 30 {
		if err := root.Remove(lockFileName); err != nil {
			return err
		}
		return nil
	}
	return errRecoverLock
}
