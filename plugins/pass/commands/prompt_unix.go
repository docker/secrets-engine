// Copyright 2026 Docker, Inc.
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

//go:build !windows

package commands

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/charmbracelet/x/term"
	"golang.org/x/sys/unix"
)

func enterRaw(f *os.File) (*term.State, error) {
	state, err := term.GetState(f.Fd())
	if err != nil {
		return nil, err
	}
	raw := state.Termios
	// cfmakeraw(3)
	raw.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	raw.Oflag &^= unix.OPOST
	raw.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	raw.Cflag &^= unix.CSIZE | unix.PARENB
	raw.Cflag |= unix.CS8
	raw.Cc[unix.VMIN] = 1
	raw.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(int(f.Fd()), setTermiosNow, &raw); err != nil {
		return nil, err
	}
	return state, nil
}

func restoreTerminal(f *os.File, state *term.State) error {
	return unix.IoctlSetTermios(int(f.Fd()), setTermiosFlush, &state.Termios)
}

var errBeyondSelect = errors.New("cannot watch the terminal: a descriptor is beyond select(2)'s range")

type terminalInput struct {
	ctx  context.Context
	f    *os.File
	fd   int32
	wake int32  // the pipe's read end: readable once ctx is done
	stop func() // ends the goroutine behind the pipe and closes it
	// selects is set once poll(2) reported POLLNVAL for the terminal, as it
	// does for /dev/tty on macOS; select(2) watches it from then on.
	selects bool
}

func newTerminalInput(ctx context.Context, f *os.File) (*terminalInput, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	done, exited := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(exited)
		select {
		case <-ctx.Done():
			_, _ = w.Write([]byte{0})
		case <-done:
		}
	}()
	stop := sync.OnceFunc(func() {
		close(done)
		<-exited
		_ = w.Close()
		_ = r.Close()
	})
	return &terminalInput{ctx: ctx, f: f, fd: int32(f.Fd()), wake: int32(r.Fd()), stop: stop}, nil
}

func (t *terminalInput) close() { t.stop() }

func (t *terminalInput) Read(p []byte) (int, error) { return t.f.Read(p) }

func (t *terminalInput) wait(d time.Duration) (bool, error) {
	var deadline time.Time
	if d > 0 {
		deadline = time.Now().Add(d)
	}
	for {
		left := time.Duration(-1) // no limit
		if d > 0 {
			if left = time.Until(deadline); left <= 0 {
				return false, nil
			}
		}
		ready, err := t.watch(left)
		if errors.Is(err, unix.EINTR) { // a signal: neither call is restarted
			continue
		}
		return ready, err
	}
}

// watch waits for input or the wake-up for left, without limit when left < 0.
func (t *terminalInput) watch(left time.Duration) (bool, error) {
	if t.selects {
		return t.selectWatch(left)
	}
	timeout := -1 // no limit
	if left >= 0 {
		timeout = int((left + time.Millisecond - 1) / time.Millisecond)
	}
	fds := []unix.PollFd{{Fd: t.fd, Events: unix.POLLIN}, {Fd: t.wake, Events: unix.POLLIN}}
	n, err := unix.Poll(fds, timeout)
	switch {
	case err != nil:
		return false, err
	case n == 0:
		return false, nil
	case fds[1].Revents != 0: // written once ctx is done
		return false, t.ctx.Err()
	case fds[0].Revents&unix.POLLNVAL != 0:
		// poll(2) cannot watch the terminal, as macOS says of /dev/tty, and
		// returned at once. select(2) can, and gets the time left.
		t.selects = true
		return t.selectWatch(left)
	}
	return true, nil // input, or a hangup or error for the read to report
}

// selectWatch is watch by select(2), for a terminal poll(2) cannot watch.
func (t *terminalInput) selectWatch(left time.Duration) (bool, error) {
	if t.fd >= unix.FD_SETSIZE || t.wake >= unix.FD_SETSIZE {
		return false, errBeyondSelect
	}
	var timeout *unix.Timeval // no limit
	if left >= 0 {
		tv := unix.NsecToTimeval(int64(left))
		timeout = &tv
	}
	var set unix.FdSet
	set.Set(int(t.fd))
	set.Set(int(t.wake))
	n, err := unix.Select(int(max(t.fd, t.wake))+1, &set, nil, nil, timeout)
	switch {
	case err != nil:
		return false, err
	case n == 0:
		return false, nil
	case set.IsSet(int(t.wake)): // written once ctx is done
		return false, t.ctx.Err()
	}
	return true, nil // input, or a hangup or error for the read to report
}
