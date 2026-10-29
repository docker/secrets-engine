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
	"encoding/binary"
	"unicode/utf16"
	"unicode/utf8"
)

func Encode(src []byte) []byte {
	dst := make([]byte, 0, 2*len(src))
	for len(src) > 0 {
		r, size := utf8.DecodeRune(src)
		src = src[size:]
		if r > 0xFFFF {
			r1, r2 := utf16.EncodeRune(r)
			dst = binary.LittleEndian.AppendUint16(dst, uint16(r1))
			dst = binary.LittleEndian.AppendUint16(dst, uint16(r2))
			continue
		}
		dst = binary.LittleEndian.AppendUint16(dst, uint16(r))
	}
	return dst
}

func Decode(src []byte) []byte {
	dst := make([]byte, 0, 3*((len(src)+1)/2))
	for len(src) >= 2 {
		r := rune(binary.LittleEndian.Uint16(src))
		n := 2
		if utf16.IsSurrogate(r) && len(src) >= 4 {
			if r2 := rune(binary.LittleEndian.Uint16(src[2:])); isLowSurrogate(r2) {
				r = utf16.DecodeRune(r, r2)
				n = 4
			}
		}
		dst = utf8.AppendRune(dst, r)
		src = src[n:]
	}
	if len(src) == 1 {
		dst = utf8.AppendRune(dst, utf8.RuneError)
	}
	return dst
}

func isLowSurrogate(r rune) bool {
	return 0xDC00 <= r && r <= 0xDFFF
}
