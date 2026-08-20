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

package secrets

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDedupe(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "double star spans single star",
			input:    []string{"**", "a/*"},
			expected: []string{"**"},
		},
		{
			name:     "literal tail subsumed by star tail",
			input:    []string{"a/**", "b", "c/*/a", "c/*/*"},
			expected: []string{"a/**", "b", "c/*/*"},
		},
		{
			name:     "equivalent spellings keep first occurrence",
			input:    []string{"**/*", "*/**", "**"},
			expected: []string{"**/*"},
		},
		{
			name:     "star grid collapses to most general",
			input:    []string{"a/b", "a/*", "*/b", "*/*"},
			expected: []string{"*/*"},
		},
		{
			name:     "disjoint literals survive",
			input:    []string{"a", "b"},
			expected: []string{"a", "b"},
		},
		{
			name:     "overlap without containment keeps both",
			input:    []string{"a/**", "**/a"},
			expected: []string{"a/**", "**/a"},
		},
		{
			name:     "exact duplicates keep first occurrence",
			input:    []string{"a", "a", "b"},
			expected: []string{"a", "b"},
		},
		{
			name:     "prefix does not include sibling stars",
			input:    []string{"docker/proj1/**", "docker/*/mcp/*"},
			expected: []string{"docker/proj1/**", "docker/*/mcp/*"},
		},
		{
			name:     "chain collapses to maximum",
			input:    []string{"a/b/c", "a/b/*", "a/**", "**"},
			expected: []string{"**"},
		},
		{
			name:     "single pattern",
			input:    []string{"foo"},
			expected: []string{"foo"},
		},
		{
			name:     "empty list",
			input:    []string{},
			expected: []string{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := make([]Pattern, 0, len(tc.input))
			for _, s := range tc.input {
				input = append(input, MustParsePattern(s))
			}
			result := Dedupe(input)
			resultStrings := make([]string, 0, len(result))
			for _, p := range result {
				resultStrings = append(resultStrings, p.String())
			}
			assert.Equal(t, tc.expected, resultStrings)
		})
	}
}

func Test_includes(t *testing.T) {
	tests := []struct {
		p        string
		q        string
		expected bool
	}{
		{"**", "a/*", true},
		{"*", "a", true},
		{"a", "*", false},
		{"**", "*", true},
		{"*", "**", false},
		{"**/*", "**", true},
		{"**", "**/*", true},
		{"**/*/*", "**", false},
		{"**", "**/*/*", true},
		{"*/**", "**/a", true},
		{"a/**", "**/a", false},
		{"c/*/*", "c/*/a", true},
		{"c/*/a", "c/*/*", false},
		{"docker/proj1/**", "docker/*/mcp/*", false},
		{"docker/**", "docker/**/mcp/**", true},
		{"docker/proj1/**", "docker/**/mcp/**", false},
		{"a/*/**/b", "a/**/x/b", true},
		{"a/**/b", "a/**/x/b", true},
		{"a/**/x/b", "a/*/**/b", false},
		{"**/a/**", "*/a/*", true},
		{"*/a/*", "**/a/**", false},
		{"**/a/*/*", "*/*/a/*/*", true},
		{"*/*/*/**", "*/**/a/*/*", true},
		{"**/a/*/*", "a/*/**", false},
		{"a/**/b/**", "a/**/b/**/b", true},
		{"a/**/b/**/b", "a/**/b/**", false},
		{"**/*/**/*/**", "*/**/*", true},
		{"*/**/*", "**/*/**/*/**", true},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s includes %s", tc.p, tc.q), func(t *testing.T) {
			got := includes(canonicalize(tc.p), canonicalize(tc.q))
			assert.Equal(t, tc.expected, got, "%s includes %s", tc.p, tc.q)
		})
	}
}
