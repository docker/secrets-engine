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
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	"charm.land/bubbles/v2/cursor"
	tea "charm.land/bubbletea/v2"
)

var (
	errEmptyValue     = errors.New("no value entered")
	errMultilinePaste = errors.New("pasted value spans several lines; pipe it via STDIN instead")
)

func unwrapFile(s any) (*os.File, bool) {
	// Under `docker pass`, plugin.Run makes cobra's in and out docker's
	// streams.In and streams.Out, which hide the file behind File().
	if d, wrapped := s.(interface{ File() (*os.File, bool) }); wrapped {
		return d.File()
	}
	f, ok := s.(*os.File)
	return f, ok
}

// secretFromPrompt reads one line from the terminal with the echo masked and
// returns it as the secret for id. Empty input is an error.
//
// The prompt behaves like getpass(3) on a canonical-mode tty. What is typed
// or pasted is stored verbatim, tabs and control characters included; only
// the line discipline's editing keys are interpreted: Enter, a bare LF
// (ctrl+j) or EOF (ctrl+d) end the line, Backspace erases a character,
// ctrl+w the last word, ctrl+u the whole line, and ctrl+v inserts the next
// key literally. Keys without a text form, such as arrows, are ignored.
//
// Multi-line values are not accepted at the prompt; pipe them via STDIN. A
// bracketed paste spanning several lines fails with errMultilinePaste. When
// the terminal does not bracket pastes, the prompt cannot tell a paste from
// typing, so like getpass(3) it keeps the first line, ignores what follows,
// and flushes input still queued in the tty on exit so the shell does not
// read the rest of the paste. Pastes larger than the tty input queue can
// still spill into the shell, as they do with sudo and ssh prompts. The
// prompt never reads the clipboard itself; paste with the terminal's paste
// key.
//
// Ctrl-C cancels the prompt; the error is then context.Canceled.
func secretFromPrompt(ctx context.Context, in *os.File, out io.Writer, id string) (*secret, error) {
	if f, ok := unwrapFile(out); ok {
		out = f // bubbletea sizes and restores the terminal through the file
	}
	p := tea.NewProgram(newPromptModel(id),
		tea.WithContext(ctx),
		tea.WithInput(in),
		tea.WithOutput(out),
		tea.WithoutSignalHandler(), // the root already cancels ctx on SIGINT/SIGTERM
	)
	returnModel, err := p.Run()
	// Flush what the terminal queued after we stopped reading, as getpass(3)
	// does with TCSAFLUSH; otherwise the shell reads it.
	_ = flushInput(in)
	m, ok := returnModel.(promptModel)
	switch {
	case errors.Is(err, tea.ErrInterrupted):
		// In raw mode Ctrl-C is a key press, not a signal. Report it as the
		// cancellation it is so the root exits 130 without a message.
		return nil, context.Canceled
	case errors.Is(err, tea.ErrProgramKilled) && ctx.Err() != nil:
		return nil, ctx.Err()
	case err != nil:
		return nil, err
	case !ok:
		return nil, fmt.Errorf("unexpected prompt model %T", returnModel)
	case m.err != nil:
		return nil, m.err
	}
	return &secret{id: id, val: string(m.value)}, nil
}

type promptModel struct {
	prompt    string
	value     []byte
	cursor    cursor.Model
	err       error
	submitted bool
	literal   bool // ctrl+v was pressed: the next key is inserted verbatim
}

func newPromptModel(id string) promptModel {
	c := cursor.New()
	c.SetChar(" ")
	c.Focus()
	return promptModel{prompt: fmt.Sprintf("Enter secret for %s: ", id), cursor: c}
}

func (m promptModel) Init() tea.Cmd { return cursor.Blink }

func (m promptModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyPressMsg:
		return m.keyPress(msg)
	case tea.PasteMsg:
		m.literal = false // a paste spends the ctrl+v quote, as LNEXT does on the next byte
		if m.submitted {
			return m, nil
		}
		content := strings.TrimRight(msg.Content, "\r\n")
		if strings.ContainsAny(content, "\r\n") {
			m.err = errMultilinePaste
			return m, tea.Quit
		}
		m.value = append(m.value, content...)
		return m.edited()
	}
	var cmd tea.Cmd
	m.cursor, cmd = m.cursor.Update(msg)
	return m, cmd
}

func (m promptModel) keyPress(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	// Dispatch on code and modifiers, not on names: bubbletea requests key
	// disambiguation, so capable terminals report Shift+Enter as
	// "shift+enter" and ctrl+m as "ctrl+m", where a canonical tty sees CR
	// for both. Shift never reaches a tty on these keys, so drop it.
	code, mod := msg.Code, msg.Mod&^tea.ModShift
	ctrl := func(r rune) bool { return mod == tea.ModCtrl && code == r }
	switch {
	case ctrl('c'):
		return m, tea.Interrupt
	case m.submitted:
		// Keys decoded from the same read as Enter race tea.Quit: the tail
		// of an unbracketed paste. Keep the first line only.
		return m, nil
	case m.literal:
		b := literalBytes(msg)
		if b == nil {
			return m, nil // no byte form, an arrow say: the quote stays armed
		}
		m.literal = false
		m.value = append(m.value, b...)
		return m.edited()
	}
	switch {
	case code == tea.KeyEnter, ctrl('m'), ctrl('j'), ctrl('d'):
		// CR with any modifier, LF and EOF end the line in canonical mode;
		// some terminals paste newlines as LF.
		if len(m.value) == 0 {
			m.err = errEmptyValue
		}
		m.submitted = true
		return m, tea.Quit
	case ctrl('v'):
		m.literal = true
		return m, nil
	case code == tea.KeyBackspace, ctrl('h'):
		_, n := utf8.DecodeLastRune(m.value)
		m.value = m.value[:len(m.value)-n]
	case ctrl('w'):
		m.value = trimLastWord(m.value)
	case ctrl('u'):
		m.value = m.value[:0]
	case code == tea.KeyTab && msg.Mod == 0, ctrl('i'):
		// Shift+Tab is backtab (CSI Z), which a tty would store as garbage.
		m.value = append(m.value, '\t')
	default:
		m.value = append(m.value, msg.Text...) // empty for keys without a text form
	}
	return m.edited()
}

// edited shows the cursor solid for a moment after a keystroke, then blinks.
func (m promptModel) edited() (promptModel, tea.Cmd) {
	m.cursor.IsBlinked = false
	return m, m.cursor.Blink()
}

// literalBytes is what a key press would have been as raw tty input: its
// text, the C0 byte a terminal sends for ctrl+<key>, the single-byte special
// keys, and for alt the ESC prefix of a "meta sends escape" terminal. nil
// means the key has no byte form, such as an arrow.
func literalBytes(msg tea.KeyPressMsg) []byte {
	switch {
	case msg.Text != "":
		return []byte(msg.Text)
	case msg.Mod&tea.ModAlt != 0:
		if b := literalBytes(withoutAlt(msg)); b != nil {
			return append([]byte{0x1b}, b...)
		}
		return nil
	}
	code, mod := msg.Code, msg.Mod&^tea.ModShift
	switch {
	case mod == tea.ModCtrl && isControlKey(code):
		return []byte{byte(code) & 0x1f} // ctrl+@ or ctrl+space is NUL, ctrl+[ \ ] ^ _ are 0x1b-0x1f
	case code == tea.KeyTab:
		return []byte{'\t'}
	case code == tea.KeyEnter:
		return []byte{'\r'}
	case code == tea.KeyEscape:
		return []byte{0x1b}
	case code == tea.KeyBackspace:
		return []byte{0x7f}
	}
	return nil
}

// isControlKey reports whether ctrl+<code> has a C0 byte on a terminal.
func isControlKey(code rune) bool {
	return code == tea.KeySpace || code >= '@' && code <= '_' || code >= 'a' && code <= 'z'
}

// withoutAlt is the key as typed without alt. The decoder blanks the text of
// alt combinations and lowercases shifted letters, so rebuild both.
func withoutAlt(msg tea.KeyPressMsg) tea.KeyPressMsg {
	msg.Mod &^= tea.ModAlt
	if msg.Mod&^tea.ModShift == 0 && unicode.IsPrint(msg.Code) {
		r := msg.Code
		if msg.Mod&tea.ModShift != 0 {
			r = unicode.ToUpper(r)
		}
		msg.Text = string(r)
	}
	return msg
}

// trimLastWord erases the trailing blanks and the word before them, as the
// tty's WERASE does.
func trimLastWord(b []byte) []byte {
	i := len(b)
	for i > 0 && (b[i-1] == ' ' || b[i-1] == '\t') {
		i--
	}
	for i > 0 && b[i-1] != ' ' && b[i-1] != '\t' {
		i--
	}
	return b[:i]
}

func (m promptModel) View() tea.View {
	masked := strings.Repeat("*", utf8.RuneCount(m.value))
	return tea.NewView(m.prompt + masked + m.cursor.View() + "\n")
}
