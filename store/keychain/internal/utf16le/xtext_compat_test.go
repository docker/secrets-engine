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
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

func xtextEncode(t *testing.T, in []byte) []byte {
	t.Helper()
	out, _, err := transform.Bytes(unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder(), in)
	require.NoError(t, err)
	return out
}

func xtextDecode(t *testing.T, in []byte) []byte {
	t.Helper()
	out, _, err := transform.Bytes(unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder(), in)
	require.NoError(t, err)
	return out
}

func TestCasesMatchXText(t *testing.T) {
	for _, tc := range encodeCases {
		t.Run("encode "+tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, xtextEncode(t, tc.in))
		})
	}
	for _, tc := range decodeCases {
		t.Run("decode "+tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, xtextDecode(t, tc.in))
		})
	}
}

func FuzzMatchesXText(f *testing.F) {
	for _, tc := range encodeCases {
		f.Add(tc.in)
	}
	for _, tc := range decodeCases {
		f.Add(tc.in)
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		require.Equal(t, xtextEncode(t, in), Encode(in))
		require.Equal(t, xtextDecode(t, in), Decode(in))
	})
}
