// Copyright 2025-2026 Docker, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
	lockFileName = ".posixage.lock"
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

	if err = lockFile(fl.Fd(), exclusive); err == nil {
		// truncate to update the modtime to signal to other processes that the
		// current lock is valid so they don't attempt a recovery on it.
		_ = fl.Truncate(0)
		return sync.OnceValue(func() error {
			return unlockFile(fl)
		}), nil
	}
	err = errors.Join(ErrLockUnsuccessful, err)

	if ctx.Err() == nil {
		if recoverErr := recoverStaleLock(root, fl); recoverErr != nil && !errors.Is(recoverErr, errRecoverLock) {
			return nil, errors.Join(err, recoverErr)
		}
		fl = nil

		fl, err = openFile(root)
		if err != nil {
			return nil, err
		}
	}

	if ctx.Err() != nil {
		return nil, errors.Join(err, ctx.Err())
	}

	err = retryLock(ctx, fl, exclusive)
	if err != nil {
		return nil, err
	}

	return sync.OnceValue(func() error {
		return unlockFile(fl)
	}), nil
}

// retryLock attempts to acquire an advisory lock on the given file
// using flock, retrying until the context is canceled or the lock is acquired.
//
// Retries use exponential backoff with a maximum delay of 100ms
// between attempts.
//
// Set exclusive to true for write or delete operations to prevent
// concurrent reads.
func retryLock(ctx context.Context, f *os.File, exclusive bool) error {
	ep := backoff.NewExponentialBackOff()
	ep.InitialInterval = time.Millisecond * 10
	ep.MaxInterval = time.Millisecond * 100
	_, err := backoff.Retry(ctx, func() (bool, error) {
		if err := lockFile(f.Fd(), exclusive); err != nil {
			return false, err
		}
		return true, nil
	}, backoff.WithBackOff(ep), backoff.WithMaxElapsedTime(0))
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
// acquired immediately, the function retries until ctx is canceled or the
// lock is acquired.
//
// As a safeguard, the function attempts to recover from stale locks,
// defined as lock files older than 30s. Stale lock recovery is skipped when
// ctx has been canceled. If recovery fails, manual intervention may be
// required.
//
// It returns an unlock function that must be called to release the lock.
func TryLock(ctx context.Context, root *os.Root) (UnlockFunc, error) {
	return tryLock(ctx, root, true)
}

// TryRLock acquires a non-exclusive advisory lock on a lock file.
//
// If the file does not exist, it is created. If the lock cannot be
// acquired immediately, the function retries until ctx is canceled or the
// lock is acquired.
//
// As a safeguard, the function attempts to recover from stale locks,
// defined as lock files older than 30s. Stale lock recovery is skipped when
// ctx has been canceled. If recovery fails, manual intervention may be
// required.
//
// It returns an unlock function that must be called to release the lock.
func TryRLock(ctx context.Context, root *os.Root) (UnlockFunc, error) {
	return tryLock(ctx, root, false)
}
