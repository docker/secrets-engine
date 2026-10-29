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

package utf16le

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var encodeCases = []struct {
	name string
	in   []byte
	want []byte
}{
	{"empty", []byte{}, []byte{}},
	{"nul", []byte{0x00}, []byte{0x00, 0x00}},
	{"ascii", []byte("A"), []byte{0x41, 0x00}},
	{"latin-1", []byte("h\u00e9llo"), []byte{0x68, 0x00, 0xE9, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00}},
	{"bmp three byte", []byte("\u20ac"), []byte{0xAC, 0x20}},
	{"supplementary plane", []byte("\U0001F600"), []byte{0x3D, 0xD8, 0x00, 0xDE}},
	{"bom is kept", []byte("\uFEFFA"), []byte{0xFF, 0xFE, 0x41, 0x00}},
	{"max bmp", []byte("\uFFFF"), []byte{0xFF, 0xFF}},
	{"max rune", []byte("\U0010FFFF"), []byte{0xFF, 0xDB, 0xFF, 0xDF}},
	{"invalid byte", []byte{0xFF}, []byte{0xFD, 0xFF}},
	{"invalid byte between ascii", []byte{'a', 0x80, 'b'}, []byte{0x61, 0x00, 0xFD, 0xFF, 0x62, 0x00}},
	{"truncated sequence", []byte{0xE2, 0x82}, []byte{0xFD, 0xFF, 0xFD, 0xFF}},
	{"utf-8 encoded surrogate", []byte{0xED, 0xA0, 0x80}, []byte{0xFD, 0xFF, 0xFD, 0xFF, 0xFD, 0xFF}},
	{"overlong encoding", []byte{0xC0, 0xAF}, []byte{0xFD, 0xFF, 0xFD, 0xFF}},
}

var decodeCases = []struct {
	name string
	in   []byte
	want []byte
}{
	{"empty", []byte{}, []byte{}},
	{"nul", []byte{0x00, 0x00}, []byte{0x00}},
	{"ascii", []byte{0x41, 0x00}, []byte("A")},
	{"latin-1", []byte{0x68, 0x00, 0xE9, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00}, []byte("h\u00e9llo")},
	{"bmp three byte", []byte{0xAC, 0x20}, []byte("\u20ac")},
	{"surrogate pair", []byte{0x3D, 0xD8, 0x00, 0xDE}, []byte("\U0001F600")},
	{"bom is kept", []byte{0xFF, 0xFE, 0x41, 0x00}, []byte("\uFEFFA")},
	{"max rune", []byte{0xFF, 0xDB, 0xFF, 0xDF}, []byte("\U0010FFFF")},
	{"single byte", []byte{0x41}, []byte("\uFFFD")},
	{"odd trailing byte", []byte{0x41, 0x00, 0x42}, []byte("A\uFFFD")},
	{"lone high surrogate at end", []byte{0x3D, 0xD8}, []byte("\uFFFD")},
	{"lone high surrogate then odd byte", []byte{0x3D, 0xD8, 0x41}, []byte("\uFFFD\uFFFD")},
	{"lone high surrogate before ascii", []byte{0x3D, 0xD8, 0x41, 0x00}, []byte("\uFFFDA")},
	{"two high surrogates before low", []byte{0x3D, 0xD8, 0x3D, 0xD8, 0x00, 0xDE}, []byte("\uFFFD\U0001F600")},
	{"lone low surrogate", []byte{0x00, 0xDE}, []byte("\uFFFD")},
	{"two low surrogates become one replacement", []byte{0x00, 0xDE, 0x00, 0xDE}, []byte("\uFFFD")},
	{"three low surrogates", []byte{0x00, 0xDE, 0x00, 0xDE, 0x00, 0xDE}, []byte("\uFFFD\uFFFD")},
}

func TestEncode(t *testing.T) {
	for _, tc := range encodeCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, Encode(tc.in))
		})
	}
}

func TestDecode(t *testing.T) {
	for _, tc := range decodeCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, Decode(tc.in))
		})
	}
}

func TestDoesNotReallocate(t *testing.T) {
	for _, in := range [][]byte{
		[]byte(strings.Repeat("a", 4096)),
		[]byte(strings.Repeat("\U0001F600", 1024)),
		[]byte(strings.Repeat("\xff", 4096)),
	} {
		encoded := Encode(in)
		assert.Equal(t, 2*len(in), cap(encoded))
	}
	for _, in := range [][]byte{
		[]byte(strings.Repeat("\x41\x00", 2048)),
		[]byte(strings.Repeat("\x00\xde", 2048)),
		[]byte(strings.Repeat("\x00\xd8", 2048) + "\x41"),
	} {
		decoded := Decode(in)
		assert.Equal(t, 3*((len(in)+1)/2), cap(decoded))
	}
}

func FuzzRoundTrip(f *testing.F) {
	for _, tc := range encodeCases {
		f.Add(tc.in)
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		encoded := Encode(in)
		require.Zero(t, len(encoded)%2)
		require.LessOrEqual(t, len(encoded), 2*len(in))
		require.Equal(t, []byte(string([]rune(string(in)))), Decode(encoded))
	})
}

func FuzzDecode(f *testing.F) {
	for _, tc := range decodeCases {
		f.Add(tc.in)
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		decoded := Decode(in)
		require.True(t, utf8.Valid(decoded))
		require.LessOrEqual(t, len(decoded), 3*((len(in)+1)/2))
	})
}
