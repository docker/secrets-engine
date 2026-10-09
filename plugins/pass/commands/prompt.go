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
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	secrets "github.com/docker/secrets-engine/store"
)

var (
	errEmptyValue     = errors.New("no value entered")
	errMultilinePaste = errors.New("pasted value spans several lines; pipe it via STDIN instead")
	errPastLineEnd    = errors.New("input continued past the line end; pipe a multi-line value via STDIN instead")
	errControlChars   = errors.New("value contains control characters; pipe it via STDIN instead")
	errInvalidUTF8    = errors.New("value is not valid UTF-8; pipe it via STDIN instead")
	errSwallowedInput = errors.New("escape sequence or Alt chord swallowed part of the input; enter the value again")
)

const (
	bell  = 0x07
	ctrlC = 0x03
	ctrlD = 0x04
	ctrlU = 0x15
	esc   = 0x1b
	del   = 0x7f // Backspace; some terminals send '\b'

	bracketedPasteOn  = "\x1b[?2004h"
	bracketedPasteOff = "\x1b[?2004l"
	pasteStart        = "200" // parameter of ESC[200~
	pasteEnd          = "\x1b[201~"

	escTimeout  = 50 * time.Millisecond
	tailTimeout = 500 * time.Millisecond
)

var (
	errEscapeKey = errors.New("escape key")
	errChord     = errors.New("escape chord")
)

func unwrapFile(s any) (*os.File, bool) {
	// docker's streams.In and streams.Out hide the file behind File().
	if d, wrapped := s.(interface{ File() (*os.File, bool) }); wrapped {
		return d.File()
	}
	f, ok := s.(*os.File)
	return f, ok
}

type input interface {
	io.Reader
	wait(d time.Duration) (ready bool, err error)
}

// secretFromPrompt reads one masked line from the terminal as the value for
// id. Raw mode is entered and left with TCSAFLUSH, as getpass(3) does, so
// echoed type-ahead is dropped and a paste's tail never reaches the shell.
// Printable runes echo as '*', Backspace and ctrl+u edit, Enter submits,
// Ctrl-C cancels with context.Canceled, Ctrl-D or EOF is io.ErrUnexpectedEOF,
// escape sequences and unbound control keys are skipped. Whatever else would
// alter the value in silence is an error: a chord that swallowed text, input
// trailing Enter, a paste spanning lines, control characters, invalid UTF-8.
// Cancelling ctx restores the terminal and returns ctx.Err(); a terminal that
// cannot be restored is an error even after a value was read. No read of the
// terminal outlives the prompt: the line typed next is the shell's.
func secretFromPrompt(ctx context.Context, in *os.File, out io.Writer, id secrets.ID) (s *setPayload, err error) {
	src, err := newTerminalInput(ctx, in)
	if err != nil {
		return nil, err
	}
	defer src.close()
	state, err := enterRaw(in)
	if err != nil {
		return nil, err
	}
	defer func() {
		eol := "\r\n"
		if ctx.Err() != nil {
			eol = "" // the root ends the line on a signal
		}
		_, _ = io.WriteString(out, bracketedPasteOff+eol)
		if rerr := restoreTerminal(in, state); rerr != nil && err == nil {
			s, err = nil, fmt.Errorf("restoring the terminal: %w; run reset to recover it", rerr)
		}
	}()
	_, _ = fmt.Fprintf(out, "Enter secret for %s: %s", id.String(), bracketedPasteOn)
	val, err := readSecretLine(src, out)
	if err != nil {
		return nil, err
	}
	return &setPayload{val: val}, nil
}

func readSecretLine(in input, echo io.Writer) (string, error) {
	lr := newLineReader(in)
	defer lr.zero()
	ed := &lineEditor{echo: echo}
	defer ed.zero()
	for {
		r, err := lr.readRune()
		switch {
		case errors.Is(err, io.EOF), err == nil && r == ctrlD:
			return "", io.ErrUnexpectedEOF
		case err != nil:
			return "", err
		case r == '\r' || r == '\n':
			return ed.submit(lr)
		case r == ctrlC:
			return "", context.Canceled
		case r == del || r == '\b':
			ed.backspace()
		case r == ctrlU:
			ed.reset()
		case r == esc:
			if err := ed.escape(lr); err != nil {
				return "", err
			}
		case isC1(r): // no key sends one: mangled text
			return "", errControlChars
		case isControlRune(r):
			// unbound control key; tab is text
		default:
			ed.insert(r)
		}
	}
}

type lineEditor struct {
	val  []rune
	echo io.Writer
}

func (ed *lineEditor) emit(s string) { _, _ = io.WriteString(ed.echo, s) }

func (ed *lineEditor) insert(r rune) {
	if len(ed.val) == cap(ed.val) {
		// append would retire the full array as is: grow by hand and zero it
		grown := make([]rune, len(ed.val), max(2*cap(ed.val), 64))
		copy(grown, ed.val)
		clear(ed.val)
		ed.val = grown
	}
	ed.val = append(ed.val, r)
	ed.emit("*")
}

func (ed *lineEditor) backspace() {
	if n := len(ed.val); n > 0 {
		ed.val[n-1] = 0 // not left behind in the backing array
		ed.val = ed.val[:n-1]
		ed.emit("\b \b")
	}
}

func (ed *lineEditor) reset() {
	ed.emit(strings.Repeat("\b \b", len(ed.val)))
	ed.zero()
	ed.val = ed.val[:0]
}

func (ed *lineEditor) escape(lr *lineReader) error {
	paste, ok, err := lr.escape()
	if err != nil || !ok {
		return err
	}
	return ed.paste(paste)
}

func (ed *lineEditor) paste(content []byte) error {
	defer clear(content)
	content = bytes.TrimRight(content, "\r\n")
	switch {
	case bytes.ContainsAny(content, "\r\n"):
		return errMultilinePaste
	case bytes.IndexFunc(content, isControlRune) >= 0:
		return errControlChars
	case !utf8.Valid(content):
		return errInvalidUTF8
	}
	for len(content) > 0 {
		r, size := utf8.DecodeRune(content)
		content = content[size:]
		ed.insert(r)
	}
	return nil
}

func isControlRune(r rune) bool { return r != '\t' && unicode.IsControl(r) }

func isC1(r rune) bool { return 0x80 <= r && r <= 0x9f }

func (ed *lineEditor) submit(lr *lineReader) (string, error) {
	more, err := lr.trailing()
	switch {
	case err != nil:
		return "", err
	case more:
		return "", errPastLineEnd
	case len(ed.val) == 0:
		return "", errEmptyValue
	}
	return string(ed.val), nil
}

// zero clears the runes collected, the backing array whole: a rune dropped
// since the last growth may sit past the length.
func (ed *lineEditor) zero() { clear(ed.val[:cap(ed.val)]) }

type lineReader struct {
	src  input
	buf  [4096]byte
	r, w int
	// escapeAt is when a lone ESC last passed for the Escape key.
	escapeAt time.Time
	// tail is set when the ESC readRune last returned stood for a '[' or
	// 'O' taken for that ESC's late tail.
	tail bool
}

func newLineReader(src input) *lineReader { return &lineReader{src: src} }

func (lr *lineReader) zero() {
	clear(lr.buf[:])
	lr.r, lr.w = 0, 0
}

// trailing reports input other than line breaks within escTimeout of the
// line end. A Ctrl-C among it cancels, as it does everywhere else.
func (lr *lineReader) trailing() (bool, error) {
	deadline := time.Now().Add(escTimeout)
	for {
		rest := lr.buf[lr.r:lr.w]
		switch {
		case bytes.IndexByte(rest, ctrlC) >= 0:
			return false, context.Canceled
		case len(bytes.Trim(rest, "\r\n")) > 0:
			return true, nil
		}
		wait := time.Until(deadline)
		if wait <= 0 {
			return false, nil
		}
		more, err := lr.fill(wait)
		if err != nil && !errors.Is(err, io.EOF) {
			return false, err
		}
		if !more {
			return false, nil
		}
	}
}

// fill awaits input for wait, without limit when wait <= 0, and reads what
// came. It reports false when the wait ran out, with no read left in flight.
func (lr *lineReader) fill(wait time.Duration) (bool, error) {
	if lr.r > 0 {
		lr.w = copy(lr.buf[:], lr.buf[lr.r:lr.w])
		lr.r = 0
	}
	ready, err := lr.src.wait(wait)
	if err != nil || !ready {
		return false, err
	}
	n, err := lr.src.Read(lr.buf[lr.w:])
	lr.w += n
	switch {
	case n > 0:
		return true, nil
	case err == nil:
		return false, io.ErrNoProgress
	default:
		return false, err
	}
}

func (lr *lineReader) readByte(wait time.Duration) (byte, error) {
	if lr.r == lr.w {
		more, err := lr.fill(wait)
		switch {
		case errors.Is(err, io.EOF):
			return 0, io.ErrUnexpectedEOF
		case err != nil:
			return 0, err
		case !more:
			return 0, errChord
		}
	}
	b := lr.buf[lr.r]
	lr.r++
	return b, nil
}

func (lr *lineReader) decodeRune() (rune, int, error) {
	for !utf8.FullRune(lr.buf[lr.r:lr.w]) {
		var wait time.Duration
		if lr.r < lr.w {
			wait = escTimeout
		}
		more, err := lr.fill(wait)
		if err != nil {
			return 0, 0, err
		}
		if !more {
			return utf8.RuneError, 1, nil
		}
	}
	r, size := utf8.DecodeRune(lr.buf[lr.r:lr.w])
	return r, size, nil
}

// readRune returns the next rune. Invalid UTF-8 is errInvalidUTF8, unless a
// Ctrl-C queued behind it cancels. A '[' or 'O' within tailTimeout of a lone
// ESC is its sequence's tail and comes back as that ESC, unconsumed, with
// lr.tail set: escape then takes a paste from it and nothing else, since a
// key's sequence split from its ESC and '[' or 'O' typed after Escape look
// alike, and skipping the pair as a key would lose the text in silence.
func (lr *lineReader) readRune() (rune, error) {
	r, size, err := lr.decodeRune()
	if err != nil {
		return 0, err
	}
	lr.tail = (r == '[' || r == 'O') && time.Since(lr.escapeAt) < tailTimeout
	lr.escapeAt = time.Time{}
	if lr.tail {
		return esc, nil
	}
	lr.r += size
	if r == utf8.RuneError && size == 1 {
		if bytes.IndexByte(lr.buf[lr.r:lr.w], ctrlC) >= 0 {
			return 0, context.Canceled
		}
		return 0, errInvalidUTF8
	}
	return r, nil
}

func (lr *lineReader) unreadByte() { lr.r-- }

// escape parses the burst after ESC: sequences are skipped, a bracketed paste
// is returned with ok set, ESC alone is the Escape key. A control byte ends
// the burst and stays unread, so Enter and Ctrl-C get through. Printable
// bytes that complete no sequence or trail one are errSwallowedInput, as is
// a late tail's sequence unless it opens a paste.
func (lr *lineReader) escape() (paste []byte, ok bool, err error) {
	tail := lr.tail
	for {
		paste, ok, err = lr.sequence(tail)
		tail = false // any sequence next in the burst brings its own ESC
		switch {
		case errors.Is(err, errEscapeKey):
			lr.escapeAt = time.Now()
			return nil, false, nil
		case errors.Is(err, errChord):
			return nil, false, errSwallowedInput
		case err != nil || ok: // a paste is unmistakable: text may follow it
			return paste, ok, err
		}
		b, err := lr.readByte(escTimeout)
		switch {
		case errors.Is(err, errChord): // a gap ends the burst
			return nil, false, nil
		case err != nil:
			return nil, false, err
		case b == esc: // the next sequence
		case isControl(b):
			lr.unreadByte()
			return nil, false, nil
		default:
			return nil, false, errSwallowedInput
		}
	}
}

// sequence parses one sequence after ESC: errEscapeKey for ESC alone or
// before a control key, errChord for bytes that complete no sequence. With
// tail set, only a paste passes.
func (lr *lineReader) sequence(tail bool) (paste []byte, ok bool, err error) {
	for {
		b, err := lr.readByte(escTimeout)
		switch {
		case errors.Is(err, errChord): // nothing came: the Escape key
			return nil, false, errEscapeKey
		case err != nil:
			return nil, false, err
		case b == esc: // rxvt sends alt+arrow as ESC ESC [ A
			continue
		case isControl(b): // Escape then a key
			lr.unreadByte()
			return nil, false, errEscapeKey
		case b == '[':
			return lr.csi(tail)
		case b == 'O': // SS3: one more byte
			return nil, false, lr.skipFinal(tail)
		case b == ']', b == 'P', b == '_', b == '^', b == 'X':
			// OSC ends with BEL or ST; DCS, APC, PM and SOS with ST
			again, err := lr.skipString(b == ']')
			if err != nil || !again {
				return nil, false, err
			}
			// cut short by a new sequence: parse it
		default: // alt+key: a swallowed rune
			return nil, false, errChord
		}
	}
}

func (lr *lineReader) csi(tail bool) (paste []byte, ok bool, err error) {
	var params []byte
	for {
		c, err := lr.readByte(escTimeout)
		switch {
		case err != nil:
			return nil, false, err
		case c == '[' && len(params) == 0: // Linux console F1-F5: ESC [ [ x
			return nil, false, lr.skipFinal(tail)
		case c >= 0x20 && c <= 0x3f: // parameter and intermediate bytes
			params = append(params, c)
		case c < 0x40 || c > 0x7e: // no sequence holds this byte
			return nil, false, lr.cut(c)
		case c == '~' && string(params) == pasteStart:
			paste, err = lr.readPaste()
			return paste, err == nil, err
		case tail: // a key's sequence or typing after Escape: no telling
			return nil, false, errSwallowedInput
		case c == 'M' && len(params) == 0: // X10 mouse report
			return nil, false, lr.skipMouseReport()
		default: // final byte
			return nil, false, nil
		}
	}
}

func (lr *lineReader) skipFinal(tail bool) error {
	c, err := lr.readByte(escTimeout)
	switch {
	case err != nil:
		return err
	case isControl(c):
		return lr.cut(c)
	case tail: // a key's sequence or typing after Escape: no telling
		return errSwallowedInput
	}
	return nil
}

func (lr *lineReader) skipMouseReport() error {
	for range 3 {
		c, err := lr.readByte(escTimeout)
		if err != nil {
			return err
		}
		if isControl(c) {
			return lr.cut(c)
		}
	}
	return nil
}

func (lr *lineReader) skipString(bel bool) (newSequence bool, err error) {
	for {
		c, err := lr.readByte(escTimeout)
		switch {
		case err != nil:
			return false, err
		case c == esc:
			d, err := lr.readByte(escTimeout)
			if err != nil {
				return false, err
			}
			if d == '\\' {
				return false, nil // ST
			}
			lr.unreadByte()
			return true, nil
		case c == bell && bel:
			return false, nil
		case isControl(c):
			return false, lr.cut(c)
		}
	}
}

func (lr *lineReader) cut(c byte) error {
	if c == ctrlC {
		return context.Canceled
	}
	lr.unreadByte()
	return errChord
}

func isControl(b byte) bool { return b < 0x20 || b == del }

func (lr *lineReader) readPaste() ([]byte, error) {
	var out []byte
	for !bytes.HasSuffix(out, []byte(pasteEnd)) {
		b, err := lr.readByte(0)
		switch {
		case err != nil:
			clear(out)
			return nil, err
		case b == ctrlC:
			clear(out)
			return nil, context.Canceled
		}
		out = append(out, b)
	}
	return out[:len(out)-len(pasteEnd)], nil
}
