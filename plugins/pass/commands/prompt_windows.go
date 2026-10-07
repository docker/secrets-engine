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

package commands

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"

	"github.com/charmbracelet/x/term"
	"golang.org/x/sys/windows"
)

const ctrlZ = 0x1a // EOF on a console, as the console reader in os takes it

var procReadConsoleInputW = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReadConsoleInputW")

func enterRaw(f *os.File) (*term.State, error) {
	if err := windows.FlushConsoleInputBuffer(windows.Handle(f.Fd())); err != nil {
		return nil, err
	}
	return term.MakeRaw(f.Fd())
}

func restoreTerminal(f *os.File, state *term.State) error {
	err := term.Restore(f.Fd(), state)
	if ferr := windows.FlushConsoleInputBuffer(windows.Handle(f.Fd())); err == nil {
		err = ferr
	}
	return err
}

type inputRecord struct {
	eventType       uint16
	_               uint16
	keyDown         int32
	repeatCount     uint16
	virtualKeyCode  uint16
	virtualScanCode uint16
	unicodeChar     uint16
	controlKeyState uint32
}

func (rec *inputRecord) char() rune {
	if rec.eventType != windows.KEY_EVENT || (rec.keyDown == 0 && rec.virtualKeyCode != windows.VK_MENU) {
		return 0
	}
	return rune(rec.unicodeChar)
}

type terminalInput struct {
	ctx    context.Context
	h      windows.Handle // console input
	cancel windows.Handle // event: set once ctx is done
	stop   func()
	buf    []byte // read, not yet returned
	hi     rune   // high surrogate awaiting its pair
}

func newTerminalInput(ctx context.Context, f *os.File) (*terminalInput, error) {
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, err
	}
	done, exited := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(exited)
		select {
		case <-ctx.Done():
			_ = windows.SetEvent(ev)
		case <-done:
		}
	}()
	t := &terminalInput{ctx: ctx, h: windows.Handle(f.Fd()), cancel: ev, buf: make([]byte, 0, 4096)}
	t.stop = sync.OnceFunc(func() {
		close(done)
		<-exited
		_ = windows.CloseHandle(ev)
		clear(t.buf[:cap(t.buf)])
	})
	return t, nil
}

func (t *terminalInput) close() { t.stop() }

func (t *terminalInput) wait(d time.Duration) (bool, error) {
	var deadline time.Time
	if d > 0 {
		deadline = time.Now().Add(d)
	}
	for len(t.buf) == 0 {
		timeout := uint32(windows.INFINITE)
		if d > 0 {
			left := time.Until(deadline)
			if left <= 0 {
				return false, nil
			}
			timeout = uint32((left + time.Millisecond - 1) / time.Millisecond)
		}
		ev, err := windows.WaitForMultipleObjects([]windows.Handle{t.h, t.cancel}, false, timeout)
		switch ev {
		case windows.WAIT_OBJECT_0: // records queued
			if err := t.readRecords(); err != nil {
				return false, err
			}
		case windows.WAIT_OBJECT_0 + 1:
			return false, t.ctx.Err()
		case uint32(windows.WAIT_TIMEOUT):
			return false, nil
		default:
			if err == nil {
				err = fmt.Errorf("waiting for console input: %#x", ev)
			}
			return false, err
		}
	}
	return true, nil
}

// readRecords takes the records queued and keeps the characters among them,
// each as often as its repeat count says.
func (t *terminalInput) readRecords() error {
	var recs [64]inputRecord
	var n uint32
	r1, _, e1 := procReadConsoleInputW.Call(uintptr(t.h), uintptr(unsafe.Pointer(&recs[0])), uintptr(len(recs)), uintptr(unsafe.Pointer(&n)))
	if r1 == 0 {
		return e1
	}
	defer clear(recs[:n])
	for i := range recs[:n] {
		r := recs[i].char()
		if r == 0 {
			continue
		}
		for range max(recs[i].repeatCount, 1) {
			t.push(r)
		}
	}
	return nil
}

func (t *terminalInput) push(r rune) {
	if hi := t.hi; hi != 0 {
		t.hi = 0
		if pair := utf16.DecodeRune(hi, r); pair != utf8.RuneError {
			t.buf = utf8.AppendRune(t.buf, pair)
			return
		}
		t.buf = appendHalf(t.buf, hi) // the half on its own
	}
	switch {
	case !utf16.IsSurrogate(r):
		t.buf = utf8.AppendRune(t.buf, r)
	case r < 0xdc00: // the high half: its pair follows
		t.hi = r
	default:
		t.buf = appendHalf(t.buf, r) // a low half on its own
	}
}

func appendHalf(p []byte, r rune) []byte {
	return append(p, 0xe0|byte(r>>12), 0x80|(byte(r>>6)&0x3f), 0x80|(byte(r)&0x3f))
}

func (t *terminalInput) Read(p []byte) (int, error) {
	for len(t.buf) == 0 {
		if _, err := t.wait(0); err != nil {
			return 0, err
		}
	}
	n := len(t.buf)
	if i := bytes.IndexByte(t.buf, ctrlZ); i >= 0 {
		if i == 0 {
			t.drop(1)
			return 0, io.EOF
		}
		n = i
	}
	n = copy(p, t.buf[:n])
	t.drop(n)
	return n, nil
}

// drop discards the first n bytes read, zeroing them.
func (t *terminalInput) drop(n int) {
	rest := copy(t.buf, t.buf[n:])
	clear(t.buf[rest:])
	t.buf = t.buf[:rest]
}
