package posixage

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/cenkalti/backoff/v5"
)

var (
	ErrLockUnsuccessful   = errors.New("store is locked")
	ErrUnlockUnsuccessful = errors.New("could not unlock store")
)

const lockFileName = ".posixage.lock"

// unlockFunc is the callback function returned by [lockFile]
// it should always be called inside a defer.
type unlockFunc func() error

// openFile is a helper function for internal use by [lockFile]
func openFile(root *os.Root) (*os.File, error) {
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
func attemptLock(root *os.Root, exclusive bool, timeout time.Duration) (unlockFunc, error) {
	fl, err := openFile(root)
	if err != nil {
		return nil, err
	}

	ep := backoff.NewExponentialBackOff()
	ep.InitialInterval = time.Millisecond * 10
	ep.MaxInterval = time.Millisecond * 100

	unlock, err := backoff.Retry(context.Background(), func() (unlockFunc, error) {
		return lockFile(fl, exclusive)
	},
		backoff.WithBackOff(ep),
		backoff.WithMaxElapsedTime(timeout),
	)
	if err != nil {
		// recoverLock closes fl
		recoverErr := recoverLock(root, fl)
		if recoverErr != nil && !errors.Is(recoverErr, errRecoverLock) {
			// we want the underlying error - something went wrong to recover
			// the file (e.g. could not remove).
			return nil, errors.Join(err, recoverErr)
		}
		if recoverErr != nil && errors.Is(recoverErr, errRecoverLock) {
			return nil, err
		}

		// we could recover, re-run the lock
		return lockFile(fl, exclusive)
	}
	return unlock, nil
}

var errRecoverLock = errors.New("lock file is not older than 30 seconds")

// recoverLock checks whether a lock file's modification time is older than
// 30 seconds. If so, it removes the file to recover from a stale lock.
//
// The file is always closed, since this function is intended to be called
// as a last resort when acquiring a lock.
//
// It returns no error if the lock file was successfully removed.
func recoverLock(root *os.Root, fl *os.File) error {
	// always close the file regardless
	defer func() { _ = fl.Close() }()

	info, err := fl.Stat()
	if err != nil {
		return err
	}

	// the lock file should not have existed for such a long time
	// it is possible that the application might have crashed before
	// let's try recover from that so that we don't lock indefinitely.
	if time.Since(info.ModTime()).Seconds() >= 30 {
		_ = fl.Close()
		if err := root.Remove(lockFileName); err != nil {
			return err
		}
		return nil
	}
	return errRecoverLock
}
