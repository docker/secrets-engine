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

package keychain

import (
	"crypto/rand"
	"encoding/base32"
	"strings"
)

var randRead = rand.Read

// RandomID returns random ID (base32) string with prefix, using 256 bits as
// recommended by tptacek: https://gist.github.com/tqbf/be58d2d39690c3b366ad
func RandomID(prefix string) (string, error) {
	buf, err := RandBytes(32)
	if err != nil {
		return "", err
	}
	str := base32.StdEncoding.EncodeToString(buf)
	str = strings.ReplaceAll(str, "=", "")
	str = prefix + str
	return str, nil
}

// RandBytes returns random bytes of length
func RandBytes(length int) ([]byte, error) {
	buf := make([]byte, length)
	if _, err := randRead(buf); err != nil {
		return nil, err
	}
	return buf, nil
}
