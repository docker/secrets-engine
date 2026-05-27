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
	"io/fs"
	"os"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v5"
)

var (
	ErrLockUnsuccessful   = errors.New("store is locked")
	ErrUnlockUnsuccessful = errors.New("could not unlock store")

	// errStaleInode indicates that the file we flocked is no longer the
	// file at the lock-file path. This happens when another caller's
	// stale-recovery unlinked the file between our open and our flock.
	// Locking an unlinked inode would leave us holding a "ghost" lock
	// that no other caller can observe.
	errStaleInode = errors.New("lock file inode changed under us")
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

// acquireOnce performs a single lock acquisition attempt and verifies the
// resulting lock is on the file currently at the lock-file path.
//
// The sequence is open -> flock -> compare-inodes -> truncate. If any step
// fails the function releases the flock (when held) and closes the fd
// before returning. The returned [os.File] is the locked descriptor; the
// caller is responsible for unlocking and closing it.
//
// The inode check is what prevents the "ghost lock" race: when a
// concurrent stale-recovery unlinks the file between our [openFile] and
// our [lockFile] call, [lockFile] will succeed on the unlinked inode but
// the path will resolve to a brand-new inode. Treating that as a failure
// forces the caller to drop the bad lock and try again with a fresh fd.
func acquireOnce(root *os.Root, exclusive bool) (*os.File, error) {
	fl, err := openFile(root)
	if err != nil {
		return nil, err
	}

	if err := lockFile(fl.Fd(), exclusive); err != nil {
		_ = fl.Close()
		return nil, err
	}

	same, err := isCurrentLockFile(fl, root)
	if err != nil {
		_ = releaseLock(fl)
		_ = fl.Close()
		return nil, err
	}
	if !same {
		_ = releaseLock(fl)
		_ = fl.Close()
		return nil, errStaleInode
	}

	// truncate to update the modtime to signal to other processes that the
	// current lock is valid so they don't attempt a recovery on it.
	_ = fl.Truncate(0)
	return fl, nil
}

// isCurrentLockFile reports whether the locked descriptor [fl] still refers
// to the file at the lock-file path. It returns false when the path no
// longer exists or has been replaced by a different inode.
func isCurrentLockFile(fl *os.File, root *os.Root) (bool, error) {
	fdInfo, err := fl.Stat()
	if err != nil {
		return false, err
	}
	pathInfo, err := root.Stat(lockFileName)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return os.SameFile(fdInfo, pathInfo), nil
}

func tryLock(ctx context.Context, root *os.Root, exclusive bool) (UnlockFunc, error) {
	fl, err := acquireOnce(root, exclusive)
	if err == nil {
		return sync.OnceValue(func() error {
			return unlockFile(fl)
		}), nil
	}
	firstErr := errors.Join(ErrLockUnsuccessful, err)

	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, errors.Join(firstErr, ctxErr)
	}

	if recoverErr := recoverStaleLock(root); recoverErr != nil && !errors.Is(recoverErr, errRecoverLock) {
		return nil, errors.Join(firstErr, recoverErr)
	}

	fl, err = retryLock(ctx, root, exclusive)
	if err != nil {
		return nil, err
	}
	return sync.OnceValue(func() error {
		return unlockFile(fl)
	}), nil
}

// retryLock loops [acquireOnce] with exponential backoff until ctx is
// canceled or a verified lock is obtained. Each iteration opens a fresh
// fd, so a [errStaleInode] result simply causes the next attempt to start
// over against whatever file is currently at the path.
func retryLock(ctx context.Context, root *os.Root, exclusive bool) (*os.File, error) {
	ep := backoff.NewExponentialBackOff()
	ep.InitialInterval = time.Millisecond * 10
	ep.MaxInterval = time.Millisecond * 100

	fl, err := backoff.Retry(ctx, func() (*os.File, error) {
		return acquireOnce(root, exclusive)
	}, backoff.WithBackOff(ep), backoff.WithMaxElapsedTime(0))
	if err != nil {
		return nil, errors.Join(ErrLockUnsuccessful, err)
	}
	return fl, nil
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
