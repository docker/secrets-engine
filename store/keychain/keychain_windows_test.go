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

//go:build windows

package keychain

import (
	"slices"
	"strings"
	"testing"

	"github.com/danieljoos/wincred"
	"github.com/stretchr/testify/assert"
)

func TestMapWindowsAttributes(t *testing.T) {
	t.Run("can map to windows attributes", func(t *testing.T) {
		attributes := map[string]string{
			"color": "green",
			"game":  "elden ring",
		}
		expected := []wincred.CredentialAttribute{
			{
				Keyword: "color",
				Value:   []byte("green"),
			},
			{
				Keyword: "game",
				Value:   []byte("elden ring"),
			},
		}
		actual := mapToWindowsAttributes(attributes)
		slices.SortFunc(actual, func(a, b wincred.CredentialAttribute) int {
			return strings.Compare(a.Keyword, b.Keyword)
		})
		assert.EqualValues(t, expected, actual)
	})
	t.Run("can map from windows attributes", func(t *testing.T) {
		wa := []wincred.CredentialAttribute{
			{
				Keyword: "color",
				Value:   []byte("green"),
			},
			{
				Keyword: "game",
				Value:   []byte("elden ring"),
			},
		}
		assert.EqualValues(t, map[string]string{
			"color": "green",
			"game":  "elden ring",
		}, mapFromWindowsAttributes(wa))
	})
	t.Run("nil attributes won't map anything", func(t *testing.T) {
		var attributes map[string]string
		assert.Empty(t, mapToWindowsAttributes(attributes))
	})
	t.Run("nil windows attributes won't map anything", func(t *testing.T) {
		var wa []wincred.CredentialAttribute
		assert.Empty(t, mapFromWindowsAttributes(wa))
	})
}
