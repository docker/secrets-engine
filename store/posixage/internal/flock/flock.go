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

	"github.com/docker/secrets-engine/x/logging"
)

// noopLogger discards every record. It is the [logging.Logger]
// implementation used when no logger is provided in the context passed
// to [TryLock] or [TryRLock], so the package never writes to the
// caller's stderr unsolicited.
type noopLogger struct{}

func (noopLogger) Printf(string, ...any) {}
func (noopLogger) Warnf(string, ...any)  {}
func (noopLogger) Errorf(string, ...any) {}

// loggerFromCtx returns the [logging.Logger] stored on ctx by
// [logging.WithLogger], or a [noopLogger] when none is set. The library
// must never log to a default sink — silence is the safe default for a
// dependency.
func loggerFromCtx(ctx context.Context) logging.Logger {
	if l, err := logging.FromContext(ctx); err == nil {
		return l
	}
	return noopLogger{}
}

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

// heartbeatInterval is how often the [heartbeat] goroutine refreshes the
// lock file's modtime while a caller holds the lock. It must be well
// below [staleThreshold] so that a holder which misses a tick or two
// (GC pause, brief scheduler starvation) still appears live to concurrent
// recovery callers.
//
// Exposed as a var rather than a const so tests can shorten it.
var heartbeatInterval = 10 * time.Second

// UnlockFunc is the callback returned by [TryLock] and [TryRLock]. It
// releases the advisory lock, closes the underlying file descriptor, and
// stops the background heartbeat goroutine that refreshes the lock
// file's modtime.
//
// Callers MUST invoke this function exactly once, typically via defer
// immediately after a successful lock acquisition. Failing to call it
// leaks both the file descriptor and the heartbeat goroutine for the
// remaining lifetime of the process — the goroutine has no other
// termination signal. Calling it more than once is safe and idempotent;
// only the first call performs the release.
//
// The returned error reflects the unlock/close step only. The heartbeat
// goroutine is always stopped and joined before the unlock is attempted,
// so the file descriptor is never touched after it has been closed.
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
// The sequence is open -> flock -> truncate -> compare-inodes. If any step
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

	// Truncate first so the modtime refresh is visible to any concurrent
	// recovery caller before we check the inode. Doing it the other way
	// round leaves a window where a passing inode check is followed by an
	// unlink before truncate, and the caller walks away with a lock on an
	// already-orphaned inode.
	_ = fl.Truncate(0)

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
	logger := loggerFromCtx(ctx)
	fl, err := acquireOnce(root, exclusive)
	if err == nil {
		return startHeartbeat(fl, root, logger), nil
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
	return startHeartbeat(fl, root, logger), nil
}

// startHeartbeat launches the modtime-refresh goroutine for a locked file
// and returns an [UnlockFunc] that stops the goroutine, waits for it to
// exit, and then unlocks/closes the file. The wait ensures the goroutine
// never touches the fd after [unlockFile] closes it.
//
// The supplied logger is used by the goroutine to surface truncate
// failures and inode-mismatch hijacks. A [noopLogger] is acceptable when
// the caller has no logging plumbed.
func startHeartbeat(fl *os.File, root *os.Root, logger logging.Logger) UnlockFunc {
	hbCtx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		heartbeat(hbCtx, fl, root, logger)
	}()
	return sync.OnceValue(func() error {
		stop()
		<-done
		return unlockFile(fl)
	})
}

// heartbeat re-truncates the locked file every [heartbeatInterval] so its
// modtime stays younger than [staleThreshold] for the lifetime of the
// lock. Without this, a holder doing work that exceeds [staleThreshold]
// would be misclassified as stale by concurrent callers, which would
// unlink the lock file and let a fresh inode be created at the same path
// — the holder-side half of the ghost-lock race.
//
// Each tick also re-verifies the locked descriptor still refers to the
// file at the lock-file path. A mismatch means we have been hijacked
// (heartbeat starved past [staleThreshold] long enough for recovery to
// fire). There is no in-band way to fail the caller's outstanding
// operation, so the mismatch is logged via the supplied [logging.Logger]
// and the goroutine keeps running — surfacing the hijack is the best we
// can do.
//
// The goroutine returns when ctx is canceled by [startHeartbeat]'s
// returned [UnlockFunc].
func heartbeat(ctx context.Context, fl *os.File, root *os.Root, logger logging.Logger) {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := fl.Truncate(0); err != nil {
				logger.Warnf("flock heartbeat: truncate failed: %v", err)
				continue
			}
			same, err := isCurrentLockFile(fl, root)
			if err != nil {
				logger.Warnf("flock heartbeat: inode verify failed: %v", err)
				continue
			}
			if !same {
				logger.Warnf("flock heartbeat: lock file inode changed under us; lock has likely been hijacked")
			}
		}
	}
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
// defined as lock files older than 30s. While the lock is held, a
// background goroutine refreshes the lock file's modtime every 10s so
// long-running operations are not misclassified as stale. Stale lock
// recovery is skipped when ctx has been canceled. If recovery fails,
// manual intervention may be required.
//
// The heartbeat goroutine surfaces truncate failures and hijack
// detections through the [logging.Logger] stored on ctx via
// [logging.WithLogger]. When no logger is set, those events are dropped
// silently — the package never writes to a default sink.
//
// On success, the returned [UnlockFunc] MUST be called exactly once to
// release the lock, close the file descriptor, and stop the heartbeat
// goroutine. The idiomatic pattern is to defer it immediately:
//
//	ctx = logging.WithLogger(ctx, myLogger) // optional
//	unlock, err := flock.TryLock(ctx, root)
//	if err != nil {
//	    return err
//	}
//	defer unlock()
//
// Failing to call the returned function leaks both the file descriptor
// and the heartbeat goroutine for the remaining lifetime of the process.
// See [UnlockFunc] for details.
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
// defined as lock files older than 30s. While the lock is held, a
// background goroutine refreshes the lock file's modtime every 10s so
// long-running operations are not misclassified as stale. Stale lock
// recovery is skipped when ctx has been canceled. If recovery fails,
// manual intervention may be required.
//
// The heartbeat goroutine surfaces truncate failures and hijack
// detections through the [logging.Logger] stored on ctx via
// [logging.WithLogger]. When no logger is set, those events are dropped
// silently — the package never writes to a default sink.
//
// On success, the returned [UnlockFunc] MUST be called exactly once to
// release the lock, close the file descriptor, and stop the heartbeat
// goroutine. The idiomatic pattern is to defer it immediately:
//
//	ctx = logging.WithLogger(ctx, myLogger) // optional
//	unlock, err := flock.TryRLock(ctx, root)
//	if err != nil {
//	    return err
//	}
//	defer unlock()
//
// Failing to call the returned function leaks both the file descriptor
// and the heartbeat goroutine for the remaining lifetime of the process.
// See [UnlockFunc] for details.
func TryRLock(ctx context.Context, root *os.Root) (UnlockFunc, error) {
	return tryLock(ctx, root, false)
}
