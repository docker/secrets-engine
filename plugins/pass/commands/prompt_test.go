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
	"io"
	"os"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// read runs the prompt's line reader over in and returns the value, the
// masked echo, and the error.
func read(t *testing.T, in io.Reader) (string, string, error) {
	t.Helper()
	var echo bytes.Buffer
	val, err := readSecretLine(testInput(t.Context(), in), &echo)
	return val, echo.String(), err
}

func Test_readSecretLine(t *testing.T) {
	t.Parallel()
	t.Run("enter submits and masks the echo", func(t *testing.T) {
		t.Parallel()
		val, echo, err := read(t, strings.NewReader("hunter2\r"))
		require.NoError(t, err)
		assert.Equal(t, "hunter2", val)
		assert.Equal(t, "*******", echo)
	})
	t.Run("bare LF submits like enter", func(t *testing.T) {
		t.Parallel()
		val, _, err := read(t, strings.NewReader("hunter2\n"))
		require.NoError(t, err)
		assert.Equal(t, "hunter2", val)
	})
	t.Run("EOF before enter does not submit", func(t *testing.T) {
		t.Parallel()
		val, _, err := read(t, strings.NewReader("hunter2"))
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
		assert.Empty(t, val)
	})
	t.Run("ctrl+d ends the prompt without a value", func(t *testing.T) {
		t.Parallel()
		// On a Windows console Ctrl-Z arrives as EOF and ends it the same way.
		val, _, err := read(t, strings.NewReader("hunter2\x04\r"))
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
		assert.Empty(t, val)
	})
	t.Run("cancelling the context ends the read", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		pr, pw := io.Pipe() // never written to: the read blocks like a quiet tty
		t.Cleanup(func() { _ = pw.Close() })
		go func() {
			time.Sleep(20 * time.Millisecond)
			cancel()
		}()
		var echo bytes.Buffer
		_, err := readSecretLine(testInput(ctx, pr), &echo)
		assert.ErrorIs(t, err, context.Canceled)
		assert.Empty(t, echo.String())
	})
	t.Run("enter on empty input errors", func(t *testing.T) {
		t.Parallel()
		_, _, err := read(t, strings.NewReader("\r"))
		assert.ErrorIs(t, err, errEmptyValue)
	})
	t.Run("ctrl+c cancels", func(t *testing.T) {
		t.Parallel()
		_, _, err := read(t, strings.NewReader("hun\x03ter2\r"))
		assert.ErrorIs(t, err, context.Canceled)
	})
	t.Run("backspace removes one rune", func(t *testing.T) {
		t.Parallel()
		val, echo, err := read(t, strings.NewReader("pä\x7fa\bs\r"))
		require.NoError(t, err)
		assert.Equal(t, "ps", val)
		assert.Equal(t, "**\b \b*\b \b*", echo)
	})
	t.Run("backspace on empty input does nothing", func(t *testing.T) {
		t.Parallel()
		val, echo, err := read(t, strings.NewReader("\x7fa\r"))
		require.NoError(t, err)
		assert.Equal(t, "a", val)
		assert.Equal(t, "*", echo)
	})
	t.Run("ctrl+u clears the line", func(t *testing.T) {
		t.Parallel()
		val, echo, err := read(t, strings.NewReader("abc\x15d\r"))
		require.NoError(t, err)
		assert.Equal(t, "d", val)
		assert.Equal(t, "***\b \b\b \b\b \b*", echo)
	})
	t.Run("escape sequences are skipped", func(t *testing.T) {
		t.Parallel()
		// Left arrow (CSI), Home (SS3), F5 (CSI with parameters), SGR
		// mouse report, cursor position report; rxvt alt+up (ESC ESC [
		// A), Linux console F1 (ESC [ [ A), X10 mouse report (ESC [ M and
		// three bytes), OSC replies ended by BEL and by ST, a DCS reply;
		// an OSC reply cut short by an arrow key. Typing resumes after a
		// gap.
		for _, seq := range []string{
			"\x1b[D", "\x1bOH", "\x1b[15~", "\x1b[<0;10;20M", "\x1b[12;40R",
			"\x1b\x1b[A", "\x1b[[A", "\x1b[M !!", "\x1b]11;rgb:0000/0000/0000\x07", "\x1b]52;c;aGVsbG8=\x1b\\", "\x1bP>|xterm(380)\x1b\\",
			"\x1b]11;rgb\x1b[D",
		} {
			t.Run(seq, func(t *testing.T) {
				t.Parallel()
				in := &chunkReader{chunks: []chunk{{data: "a" + seq}, {delay: 6 * escTimeout, data: "b\r"}}}
				val, echo, err := read(t, in)
				require.NoError(t, err)
				assert.Equal(t, "ab", val)
				assert.Equal(t, "**", echo)
			})
		}
	})
	t.Run("a control string cut short by a paste", func(t *testing.T) {
		t.Parallel()
		// A DCS reply without terminator, then a bracketed paste.
		val, echo, err := read(t, strings.NewReader("\x1bP>|xterm\x1b[200~b\x1b[201~\r"))
		require.NoError(t, err)
		assert.Equal(t, "b", val)
		assert.Equal(t, "*", echo)
	})
	t.Run("text swallowed by an escape is an error", func(t *testing.T) {
		t.Parallel()
		// Alt+h, or Escape coalesced with typing by ssh latency; the same
		// where the text opens a CSI or an SS3; alt+ä; alt with a rune cut
		// short; an arrow key with typing right behind it.
		for _, in := range []string{"\x1bhunter2\r", "\x1b[hunter2\r", "\x1bOpenSesame\r", "a\x1bäb\r", "\x1b\xc3", "a\x1b[Dab\r"} {
			_, _, err := read(t, strings.NewReader(in))
			assert.ErrorIs(t, err, errSwallowedInput, "%q", in)
		}
	})
	t.Run("a sequence cut short by a key is an error", func(t *testing.T) {
		t.Parallel()
		// Enter, Backspace or Ctrl-D right behind Alt+[ or the like.
		for _, in := range []string{"a\x1b[\r", "a\x1b[M\r", "a\x1bO\x7f", "a\x1b]11;rgb\r", "a\x1b[12;\x04"} {
			_, _, err := read(t, strings.NewReader(in))
			assert.ErrorIs(t, err, errSwallowedInput, "%q", in)
		}
	})
	t.Run("a chord cut short by a gap is an error", func(t *testing.T) {
		t.Parallel()
		// Alt+[ opens a CSI, Alt+Shift+O an SS3, Alt+Shift+P a DCS and
		// Alt+] an OSC; a CSI with parameters and an X10 mouse report cut
		// short. Nothing follows within escTimeout.
		for _, chord := range []string{"\x1b[", "\x1bO", "\x1bP", "\x1b]", "\x1b[12;", "\x1b[M "} {
			t.Run(chord, func(t *testing.T) {
				t.Parallel()
				pr, pw := io.Pipe() // nothing follows: the read blocks like a quiet tty
				t.Cleanup(func() { _ = pw.Close() })
				go func() { _, _ = pw.Write([]byte(chord)) }()
				_, _, err := read(t, pr)
				assert.ErrorIs(t, err, errSwallowedInput)
			})
		}
	})
	t.Run("escape then enter submits", func(t *testing.T) {
		t.Parallel()
		val, _, err := read(t, strings.NewReader("abc\x1b\r"))
		require.NoError(t, err)
		assert.Equal(t, "abc", val)
	})
	t.Run("ctrl+c ends a sequence cut short", func(t *testing.T) {
		t.Parallel()
		for _, in := range []string{"\x1b[\x03", "\x1b[12;\x03", "\x1b[[\x03", "\x1bO\x03", "\x1b]11;rgb\x03", "\x1bP>|xterm\x03", "\x1b[M \x03"} {
			_, _, err := read(t, strings.NewReader(in))
			assert.ErrorIs(t, err, context.Canceled, "%q", in)
		}
	})
	t.Run("a lone escape is ignored", func(t *testing.T) {
		t.Parallel()
		// Nothing follows ESC within escTimeout: the Escape key.
		in := &chunkReader{chunks: []chunk{{data: "\x1b"}, {delay: 6 * escTimeout, data: "a\r"}}}
		val, _, err := read(t, in)
		require.NoError(t, err)
		assert.Equal(t, "a", val)
	})
	t.Run("escape then enter in separate reads submits", func(t *testing.T) {
		t.Parallel()
		in := &chunkReader{chunks: []chunk{{data: "abc\x1b"}, {delay: 6 * escTimeout, data: "\r"}}}
		val, _, err := read(t, in)
		require.NoError(t, err)
		assert.Equal(t, "abc", val)
	})
	t.Run("a sequence split across reads is skipped whole", func(t *testing.T) {
		t.Parallel()
		// The rest arrives in the next read, within escTimeout: after ESC,
		// or inside the sequence.
		for _, chunks := range [][]chunk{
			{{data: "\x1b"}, {data: "[D"}, {delay: 6 * escTimeout, data: "a\r"}},
			{{data: "\x1b[1;"}, {data: "5D"}, {delay: 6 * escTimeout, data: "a\r"}},
		} {
			val, echo, err := read(t, &chunkReader{chunks: chunks})
			require.NoError(t, err, "%q", chunks)
			assert.Equal(t, "a", val, "%q", chunks)
			assert.Equal(t, "*", echo, "%q", chunks)
		}
	})
	t.Run("paste drops the trailing newline", func(t *testing.T) {
		t.Parallel()
		val, echo, err := read(t, strings.NewReader("\x1b[200~hunter2\r\n\x1b[201~\r"))
		require.NoError(t, err)
		assert.Equal(t, "hunter2", val)
		assert.Equal(t, "*******", echo)
	})
	t.Run("paste is kept verbatim", func(t *testing.T) {
		t.Parallel()
		val, _, err := read(t, strings.NewReader("\x1b[200~ a\tb \x1b[201~\r"))
		require.NoError(t, err)
		assert.Equal(t, " a\tb ", val)
	})
	t.Run("multi-line paste is rejected", func(t *testing.T) {
		t.Parallel()
		_, _, err := read(t, strings.NewReader("\x1b[200~line1\nline2\n\x1b[201~"))
		assert.ErrorIs(t, err, errMultilinePaste)
	})
	t.Run("input behind the line end in the same read is rejected", func(t *testing.T) {
		t.Parallel()
		// A multi-line paste without bracketing, or type-ahead coalesced
		// with Enter.
		for _, in := range []string{"line1\rline2\r", "line1\nline2", "line1\r\nline2\r\n"} {
			_, _, err := read(t, strings.NewReader(in))
			assert.ErrorIs(t, err, errPastLineEnd, "%q", in)
		}
	})
	t.Run("input right behind the line end in a later read is rejected too", func(t *testing.T) {
		t.Parallel()
		// A paste delivered line by line, or chunked at the line end; the
		// wait outlasts a bare line break.
		for _, chunks := range [][]chunk{
			{{data: "line1\r"}, {data: "line2\r"}},
			{{data: "line1\r"}, {data: "\n"}, {data: "line2\r\n"}},
		} {
			_, _, err := read(t, &chunkReader{chunks: chunks})
			assert.ErrorIs(t, err, errPastLineEnd, "%q", chunks)
		}
	})
	t.Run("a quiet escTimeout after enter submits", func(t *testing.T) {
		t.Parallel()
		pr, pw := io.Pipe() // nothing follows Enter: the read blocks like a quiet tty
		t.Cleanup(func() { _ = pw.Close() })
		go func() { _, _ = pw.Write([]byte("line1\r")) }()
		val, _, err := read(t, pr)
		require.NoError(t, err)
		assert.Equal(t, "line1", val)
	})
	t.Run("ctrl+c right behind enter cancels", func(t *testing.T) {
		t.Parallel()
		// Coalesced with Enter by ssh latency, or in the next read within
		// escTimeout: Ctrl-C, not input past the line end.
		_, _, err := read(t, strings.NewReader("secret\r\x03"))
		assert.ErrorIs(t, err, context.Canceled)
		_, _, err = read(t, &chunkReader{chunks: []chunk{{data: "secret\r"}, {data: "\x03"}}})
		assert.ErrorIs(t, err, context.Canceled)
	})
	t.Run("line breaks after the line end are not a paste", func(t *testing.T) {
		t.Parallel()
		for _, in := range []string{"secret\r\n", "secret\r\r", "secret\n\r\n"} {
			val, _, err := read(t, strings.NewReader(in))
			require.NoError(t, err, "%q", in)
			assert.Equal(t, "secret", val, "%q", in)
		}
	})
	t.Run("paste with control characters is rejected", func(t *testing.T) {
		t.Parallel()
		for _, in := range []string{"\x1b[200~a\x1bb\x1b[201~\r", "\x1b[200~a\x7fb\x1b[201~\r", "\x1b[200~a\x00b\x1b[201~\r", "\x1b[200~a\u0085b\x1b[201~\r"} {
			_, echo, err := read(t, strings.NewReader(in))
			assert.ErrorIs(t, err, errControlChars, "%q", in)
			assert.Empty(t, echo, "%q", in)
		}
	})
	t.Run("ctrl+c inside a paste cancels", func(t *testing.T) {
		t.Parallel()
		// Also the way out of a paste whose end marker never comes.
		for _, in := range []string{"\x1b[200~abc\x03def\x1b[201~\r", "\x1b[200~abc\x03"} {
			_, _, err := read(t, strings.NewReader(in))
			assert.ErrorIs(t, err, context.Canceled, "%q", in)
		}
	})
	t.Run("paste longer than the read buffer", func(t *testing.T) {
		t.Parallel()
		long := strings.Repeat("x", 2*len(lineReader{}.buf)+1)
		val, _, err := read(t, strings.NewReader("\x1b[200~"+long+"\x1b[201~\r"))
		require.NoError(t, err)
		assert.Equal(t, long, val)
	})
	t.Run("a paste stalled for longer than escTimeout completes", func(t *testing.T) {
		t.Parallel()
		// A paste streams at the pace of the link: no timeout inside one.
		in := &chunkReader{chunks: []chunk{{data: "\x1b[200~abc"}, {delay: 6 * escTimeout, data: "def\x1b[201~\r"}}}
		val, _, err := read(t, in)
		require.NoError(t, err)
		assert.Equal(t, "abcdef", val)
	})
	t.Run("EOF inside a paste errors", func(t *testing.T) {
		t.Parallel()
		_, _, err := read(t, strings.NewReader("\x1b[200~hunter2"))
		assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
	})
	t.Run("EOF inside a sequence errors", func(t *testing.T) {
		t.Parallel()
		for _, in := range []string{"\x1b[", "\x1b[12;", "\x1b[[", "\x1bO", "\x1b]11;rgb", "\x1bP>|x", "\x1b[M "} {
			_, _, err := read(t, strings.NewReader(in))
			assert.ErrorIs(t, err, io.ErrUnexpectedEOF, "%q", in)
		}
	})
	t.Run("ctrl+v and other control keys are ignored", func(t *testing.T) {
		t.Parallel()
		val, echo, err := read(t, strings.NewReader("a\x16\x02b\r"))
		require.NoError(t, err)
		assert.Equal(t, "ab", val)
		assert.Equal(t, "**", echo)
	})
	t.Run("a C1 control rune is an error", func(t *testing.T) {
		t.Parallel()
		// NEL and a Windows-1252 quote mark gone mojibake: no key sends
		// one, so it is text gone wrong, typed or pasted unbracketed.
		for _, in := range []string{"a\u0085b\r", "a\u0092b\r"} {
			_, echo, err := read(t, strings.NewReader(in))
			assert.ErrorIs(t, err, errControlChars, "%q", in)
			assert.Equal(t, "*", echo, "%q", in)
		}
	})
	t.Run("tab is kept, as in a paste", func(t *testing.T) {
		t.Parallel()
		val, echo, err := read(t, strings.NewReader("a\tb\r"))
		require.NoError(t, err)
		assert.Equal(t, "a\tb", val)
		assert.Equal(t, "***", echo)
	})
	t.Run("invalid UTF-8 is rejected", func(t *testing.T) {
		t.Parallel()
		// A stray byte, a lead byte without its continuation, before a key
		// or before Enter, a lone continuation byte.
		for _, in := range []string{"a\xffb\r", "a\xc3b\r", "a\xc3\r", "a\x80b\r"} {
			val, echo, err := read(t, strings.NewReader(in))
			assert.ErrorIs(t, err, errInvalidUTF8, "%q", in)
			assert.Empty(t, val, "%q", in)
			assert.Equal(t, "*", echo, "%q", in)
		}
	})
	t.Run("a lead byte on its own is invalid", func(t *testing.T) {
		t.Parallel()
		// The rest of the rune never comes: a terminal sends a rune whole.
		pr, pw := io.Pipe()
		t.Cleanup(func() { _ = pw.Close() })
		go func() { _, _ = pw.Write([]byte("a\xc3")) }()
		_, _, err := read(t, pr)
		assert.ErrorIs(t, err, errInvalidUTF8)
	})
	t.Run("ctrl+c behind a broken rune cancels", func(t *testing.T) {
		t.Parallel()
		for _, in := range []string{"a\xc3\x03", "a\xe2\x82\x03", "a\xc3b\x03"} {
			_, _, err := read(t, strings.NewReader(in))
			assert.ErrorIs(t, err, context.Canceled, "%q", in)
		}
		// Also when it arrives in the next read, within escTimeout.
		in := &chunkReader{chunks: []chunk{{data: "a\xc3"}, {data: "\x03"}}}
		_, _, err := read(t, in)
		assert.ErrorIs(t, err, context.Canceled)
	})
	t.Run("the replacement character itself is kept", func(t *testing.T) {
		t.Parallel()
		val, _, err := read(t, strings.NewReader("�\r"))
		require.NoError(t, err)
		assert.Equal(t, "�", val)
	})
	t.Run("paste with invalid UTF-8 is rejected", func(t *testing.T) {
		t.Parallel()
		_, echo, err := read(t, strings.NewReader("\x1b[200~a\xffb\x1b[201~\r"))
		assert.ErrorIs(t, err, errInvalidUTF8)
		assert.Empty(t, echo)
	})
	t.Run("a rune split across reads", func(t *testing.T) {
		t.Parallel()
		val, echo, err := read(t, iotest.OneByteReader(strings.NewReader("ä\r")))
		require.NoError(t, err)
		assert.Equal(t, "ä", val)
		assert.Equal(t, "*", echo)
	})
}

// Test_readSecretLine_lateTail covers a '[' or 'O' arriving within tailTimeout
// of a lone ESC.
func Test_readSecretLine_lateTail(t *testing.T) {
	t.Parallel()
	t.Run("a sequence tail late after its ESC is still skipped", func(t *testing.T) {
		t.Parallel()
		// A slow link splits ESC from "[D" for longer than escTimeout, yet
		// within tailTimeout.
		in := &chunkReader{chunks: []chunk{{data: "hunter2\x1b"}, {delay: 6 * escTimeout, data: "[D"}, {delay: 6 * escTimeout, data: "\r"}}}
		val, echo, err := read(t, in)
		require.NoError(t, err)
		assert.Equal(t, "hunter2", val)
		assert.Equal(t, "*******", echo)
	})
	t.Run("a bracket typed well after escape is text", func(t *testing.T) {
		t.Parallel()
		in := &chunkReader{chunks: []chunk{{data: "\x1b"}, {delay: tailTimeout + 6*escTimeout, data: "[D\r"}}}
		val, _, err := read(t, in)
		require.NoError(t, err)
		assert.Equal(t, "[D", val)
	})
	t.Run("typing right behind a late tail is an error", func(t *testing.T) {
		t.Parallel()
		in := &chunkReader{chunks: []chunk{{data: "\x1b"}, {delay: 6 * escTimeout, data: "[Dab\r"}}}
		_, _, err := read(t, in)
		assert.ErrorIs(t, err, errSwallowedInput)
	})
	t.Run("a late tail a key sends is skipped", func(t *testing.T) {
		t.Parallel()
		// Up, Home as SS3, F5, Shift-Tab, F1 as SS3 and on the Linux
		// console, rxvt's shift+up, ctrl+left; a paste split from its ESC.
		for _, tail := range []string{"[A", "OH", "[15~", "[Z", "OP", "[[A", "[a", "[1;5D", "[200~hunter2\x1b[201~"} {
			t.Run(tail, func(t *testing.T) {
				t.Parallel()
				in := &chunkReader{chunks: []chunk{{data: "\x1b"}, {delay: 6 * escTimeout, data: tail}, {delay: 6 * escTimeout, data: "a\r"}}}
				val, _, err := read(t, in)
				require.NoError(t, err)
				want := "a"
				if strings.HasPrefix(tail, "[200~") {
					want = "hunter2a"
				}
				assert.Equal(t, want, val)
			})
		}
	})
	t.Run("a late tail that no key sends is an error", func(t *testing.T) {
		t.Parallel()
		// Escape out of habit, then a value opening with 'O' or '[' whose
		// second key ssh latency coalesces with the first and a gap follows:
		// an SS3 or CSI no key sends. Also a mouse report, X10 and SGR, and
		// a terminal reply split from their ESC, since they end the same way.
		for _, tail := range []string{"Op", "[x", "[M !!", "[<0;10;20M", "[0n"} {
			t.Run(tail, func(t *testing.T) {
				t.Parallel()
				in := &chunkReader{chunks: []chunk{{data: "abc\x1b"}, {delay: 6 * escTimeout, data: tail}, {delay: 6 * escTimeout, data: "enSesame\r"}}}
				_, _, err := read(t, in)
				assert.ErrorIs(t, err, errSwallowedInput)
			})
		}
	})
}

func Test_lineEditor_zero(t *testing.T) {
	t.Parallel()
	// A rune Backspace drops leaves no trace in the backing array, and
	// neither do the runes ctrl+u clears or zero() ends with.
	ed := &lineEditor{echo: io.Discard}
	for _, r := range "hunter2x" {
		ed.insert(r)
	}
	ed.backspace()
	assert.Equal(t, "hunter2", string(ed.val))
	assert.NotContains(t, string(ed.val[:cap(ed.val)]), "x")
	ed.reset()
	assert.Empty(t, ed.val)
	assert.Equal(t, make([]rune, cap(ed.val)), ed.val[:cap(ed.val)])
	for _, r := range "abc" {
		ed.insert(r)
	}
	ed.zero()
	assert.Equal(t, make([]rune, cap(ed.val)), ed.val[:cap(ed.val)])
	// An array the value outgrows is retired zeroed, not left to append.
	ed = &lineEditor{echo: io.Discard}
	for ed.insert('a'); len(ed.val) < cap(ed.val); {
		ed.insert('a')
	}
	old := ed.val[:cap(ed.val)]
	ed.insert('b')
	assert.Equal(t, make([]rune, len(old)), old)
	assert.Equal(t, strings.Repeat("a", len(old))+"b", string(ed.val))
}

type chunk struct {
	delay time.Duration
	data  string
}

// chunkReader returns one chunk per Read, after the chunk's delay, then EOF.
type chunkReader struct{ chunks []chunk }

func (c *chunkReader) Read(p []byte) (int, error) {
	if len(c.chunks) == 0 {
		return 0, io.EOF
	}
	next := c.chunks[0]
	c.chunks = c.chunks[1:]
	time.Sleep(next.delay)
	return copy(p, next.data), nil
}

// readerInput makes an io.Reader the prompt's input for tests. A plain reader
// cannot be awaited, so a Read runs in a goroutine and the wait is on its
// result; a Read left behind when a test ends is the very thing
// terminalInput spares the terminal.
type readerInput struct {
	ctx     context.Context
	r       io.Reader
	pending chan readResult
	res     readResult // handed over, not yet read
	has     bool
}

type readResult struct {
	data []byte
	err  error
}

func testInput(ctx context.Context, r io.Reader) *readerInput {
	return &readerInput{ctx: ctx, r: r}
}

func (in *readerInput) wait(d time.Duration) (bool, error) {
	if in.has {
		return true, nil
	}
	if in.pending == nil {
		ch := make(chan readResult, 1)
		go func() {
			data := make([]byte, 4096)
			n, err := in.r.Read(data)
			ch <- readResult{data: data[:n], err: err}
		}()
		in.pending = ch
	}
	var timeout <-chan time.Time
	if d > 0 {
		timeout = time.After(d)
	}
	select {
	case in.res = <-in.pending:
		in.pending, in.has = nil, true
		return true, nil
	case <-timeout:
		return false, nil
	case <-in.ctx.Done():
		return false, in.ctx.Err()
	}
}

func (in *readerInput) Read(p []byte) (int, error) {
	for !in.has {
		if _, err := in.wait(0); err != nil {
			return 0, err
		}
	}
	n := copy(p, in.res.data)
	in.res.data = in.res.data[n:]
	if len(in.res.data) > 0 {
		return n, nil
	}
	in.has = false
	return n, in.res.err
}

// fakeInput is an input whose wait is scripted and whose reads are counted.
type fakeInput struct {
	ready bool
	err   error
	data  string
	reads int
}

func (f *fakeInput) wait(time.Duration) (bool, error) { return f.ready, f.err }

func (f *fakeInput) Read(p []byte) (int, error) {
	f.reads++
	return copy(p, f.data), nil
}

func Test_lineReader_fill(t *testing.T) {
	t.Parallel()
	t.Run("input awaited is read", func(t *testing.T) {
		t.Parallel()
		in := &fakeInput{ready: true, data: "hunter2"}
		lr := newLineReader(in)
		more, err := lr.fill(0)
		require.NoError(t, err)
		assert.True(t, more)
		assert.Equal(t, "hunter2", string(lr.buf[lr.r:lr.w]))
	})
	t.Run("a wait that runs out issues no read", func(t *testing.T) {
		t.Parallel()
		// Nothing may be left reading the terminal when the prompt returns:
		// the line typed next is the shell's.
		in := &fakeInput{data: "ls\r"}
		lr := newLineReader(in)
		more, err := lr.fill(escTimeout)
		require.NoError(t, err)
		assert.False(t, more)
		assert.Zero(t, in.reads)
	})
	t.Run("a wait ended by cancel issues no read", func(t *testing.T) {
		t.Parallel()
		in := &fakeInput{err: context.Canceled, data: "ls\r"}
		lr := newLineReader(in)
		_, err := lr.fill(0)
		require.ErrorIs(t, err, context.Canceled)
		assert.Zero(t, in.reads)
	})
	t.Run("a read that returns nothing is an error", func(t *testing.T) {
		t.Parallel()
		lr := newLineReader(&fakeInput{ready: true})
		_, err := lr.fill(0)
		assert.ErrorIs(t, err, io.ErrNoProgress)
	})
}

func Test_unwrapFile(t *testing.T) {
	t.Parallel()
	f, err := os.Open(os.DevNull)
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })
	t.Run("plain file", func(t *testing.T) {
		t.Parallel()
		got, ok := unwrapFile(f)
		require.True(t, ok)
		assert.Same(t, f, got)
	})
	t.Run("docker stream wrapper", func(t *testing.T) {
		t.Parallel()
		got, ok := unwrapFile(fileWrapper{Reader: &bytes.Buffer{}, f: f})
		require.True(t, ok)
		assert.Same(t, f, got)
	})
	t.Run("wrapper without a file", func(t *testing.T) {
		t.Parallel()
		_, ok := unwrapFile(fileWrapper{Reader: &bytes.Buffer{}})
		assert.False(t, ok)
	})
	t.Run("buffer", func(t *testing.T) {
		t.Parallel()
		_, ok := unwrapFile(&bytes.Buffer{})
		assert.False(t, ok)
	})
}

type fileWrapper struct {
	io.Reader
	f *os.File
}

func (w fileWrapper) File() (*os.File, bool) { return w.f, w.f != nil }
