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

func TestChunkBlob(t *testing.T) {
	t.Run("empty blob returns no chunks", func(t *testing.T) {
		assert.Empty(t, chunkBlob(nil, 4))
		assert.Empty(t, chunkBlob([]byte{}, 4))
	})
	t.Run("blob smaller than size is a single chunk", func(t *testing.T) {
		blob := []byte{1, 2, 3}
		chunks := chunkBlob(blob, 4)
		assert.Len(t, chunks, 1)
		assert.Equal(t, blob, chunks[0])
	})
	t.Run("blob exactly size is a single chunk", func(t *testing.T) {
		blob := []byte{1, 2, 3, 4}
		chunks := chunkBlob(blob, 4)
		assert.Len(t, chunks, 1)
		assert.Equal(t, blob, chunks[0])
	})
	t.Run("blob splits into equal chunks", func(t *testing.T) {
		blob := []byte{1, 2, 3, 4, 5, 6, 7, 8}
		chunks := chunkBlob(blob, 4)
		assert.Len(t, chunks, 2)
		assert.Equal(t, []byte{1, 2, 3, 4}, chunks[0])
		assert.Equal(t, []byte{5, 6, 7, 8}, chunks[1])
	})
	t.Run("blob splits with remainder in last chunk", func(t *testing.T) {
		blob := []byte{1, 2, 3, 4, 5}
		chunks := chunkBlob(blob, 4)
		assert.Len(t, chunks, 2)
		assert.Equal(t, []byte{1, 2, 3, 4}, chunks[0])
		assert.Equal(t, []byte{5}, chunks[1])
	})
	t.Run("reassembled chunks equal original blob", func(t *testing.T) {
		blob := make([]byte, 2560*3+100)
		for i := range blob {
			blob[i] = byte(i % 256)
		}
		chunks := chunkBlob(blob, maxBlobSize)
		assert.Len(t, chunks, 4)

		var reassembled []byte
		for _, c := range chunks {
			reassembled = append(reassembled, c...)
		}
		assert.Equal(t, blob, reassembled)
	})
}

func TestIsChunkCredential(t *testing.T) {
	t.Run("returns true when chunk:index attribute is present", func(t *testing.T) {
		attrs := []wincred.CredentialAttribute{
			{Keyword: chunkIndexKey, Value: []byte("0")},
		}
		assert.True(t, isChunkCredential(attrs))
	})
	t.Run("returns false when chunk:index attribute is absent", func(t *testing.T) {
		attrs := []wincred.CredentialAttribute{
			{Keyword: serviceGroupKey, Value: []byte("group")},
			{Keyword: serviceNameKey, Value: []byte("name")},
		}
		assert.False(t, isChunkCredential(attrs))
	})
	t.Run("returns false for empty attributes", func(t *testing.T) {
		assert.False(t, isChunkCredential(nil))
		assert.False(t, isChunkCredential([]wincred.CredentialAttribute{}))
	})
}

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
