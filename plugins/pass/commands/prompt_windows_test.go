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
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func Test_inputRecord_char(t *testing.T) {
	t.Parallel()
	key := func(down bool, vk, ch uint16) inputRecord {
		rec := inputRecord{eventType: windows.KEY_EVENT, repeatCount: 1, virtualKeyCode: vk, unicodeChar: ch}
		if down {
			rec.keyDown = 1
		}
		return rec
	}
	for name, tc := range map[string]struct {
		rec  inputRecord
		want rune
	}{
		"key press":                     {key(true, 'A', 'a'), 'a'},
		"key release":                   {key(false, 'A', 'a'), 0},
		"press of a key without a char": {key(true, 0x10 /* VK_SHIFT */, 0), 0},
		"alt release after alt+numpad":  {key(false, windows.VK_MENU, 'é'), 'é'},
		"alt release alone":             {key(false, windows.VK_MENU, 0), 0},
		"mouse event":                   {inputRecord{eventType: 0x0002 /* MOUSE_EVENT */, keyDown: 1, unicodeChar: 'a'}, 0},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, tc.rec.char())
		})
	}
}

func Test_terminalInput_push(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		in   []rune
		want string
	}{
		"text":                       {[]rune("ab"), "ab"},
		"surrogate pair":             {[]rune{0xd83d, 0xde00}, "😀"},
		"replacement character":      {[]rune{'�'}, "�"},
		"high half then text":        {[]rune{0xd83d, 'a'}, "\xed\xa0\xbda"},
		"high half then high half":   {[]rune{0xd83d, 0xd83d, 0xde00}, "\xed\xa0\xbd😀"},
		"low half alone":             {[]rune{0xde00}, "\xed\xb8\x80"},
		"high half at the end stays": {[]rune{'a', 0xd83d}, "a"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			in := &terminalInput{}
			for _, r := range tc.in {
				in.push(r)
			}
			assert.Equal(t, tc.want, string(in.buf))
		})
	}
	t.Run("a half on its own is invalid UTF-8 to the prompt", func(t *testing.T) {
		t.Parallel()
		in := &terminalInput{}
		for _, r := range []rune{'a', 0xd83d, 'b', '\r'} {
			in.push(r)
		}
		var echo bytes.Buffer
		val, err := readSecretLine(in, &echo)
		assert.ErrorIs(t, err, errInvalidUTF8)
		assert.Empty(t, val)
		assert.Equal(t, "*", echo.String())
	})
}

func Test_terminalInput_Read(t *testing.T) {
	t.Parallel()
	t.Run("ctrl+z is EOF, once, as in os", func(t *testing.T) {
		t.Parallel()
		in := &terminalInput{buf: []byte("ab\x1acd")}
		buf := make([]byte, 8)
		n, err := in.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, "ab", string(buf[:n]))
		_, err = in.Read(buf)
		assert.ErrorIs(t, err, io.EOF)
		n, err = in.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, "cd", string(buf[:n]))
	})
	t.Run("what was read is zeroed", func(t *testing.T) {
		t.Parallel()
		in := &terminalInput{buf: []byte("hunter2")}
		buf := make([]byte, 3)
		n, err := in.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, "hun", string(buf[:n]))
		assert.Equal(t, "ter2\x00\x00\x00", string(in.buf[:cap(in.buf)]))
	})
}
