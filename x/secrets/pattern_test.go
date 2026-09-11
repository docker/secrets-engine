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
	"github.com/stretchr/testify/require"
)

func TestParsePattern(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected error
	}{
		{"valid pattern with single component", "foo", nil},
		{"valid pattern with multiple components", "foo/bar/baz", nil},
		{"valid pattern only with asterisk", "*", nil},
		{"valid pattern only with double asterisk", "**", nil},
		{"valid pattern starting with asterisk", "*/bar", nil},
		{"valid pattern ending with asterisk", "foo/*/baz", nil},
		{"valid pattern starting with double asterisk", "**/bar", nil},
		{"valid pattern ending with double asterisk", "foo/**/baz", nil},
		{"valid pattern with mix of components and wildcards", "foo/*/baz/**/*", nil},
		{"invalid pattern with mix of asterisks and allowed characters v1", "*a*", ErrInvalidPattern},
		{"invalid pattern with mix of asterisks and allowed characters v2", "*a", ErrInvalidPattern},
		{"invalid pattern with leading slash", "/foo/bar", ErrInvalidPattern},
		{"invalid pattern with trailing slash", "foo/bar/", ErrInvalidPattern},
		{"invalid pattern with empty component", "foo//bar", ErrInvalidPattern},
		{"invalid empty pattern", "", ErrInvalidPattern},
		{"invalid pattern only with slash", "/", ErrInvalidPattern},
		{"invalid pattern with components and a mix of asterisks and allowed characters", "foo/*a*/baz", ErrInvalidPattern},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParsePattern(tc.input)
			assert.ErrorIs(t, err, tc.expected)
		})
	}
}

func TestPatternComparable(t *testing.T) {
	a := MustParsePattern("foo")
	b := MustParsePattern("foo")
	assert.Equal(t, a, b)
	myMap := map[Pattern]string{}
	bar := "bar"
	myMap[MustParsePattern("foo")] = bar
	assert.Equal(t, bar, myMap[a])
	assert.Equal(t, bar, myMap[b])
}

func TestPatternContains(t *testing.T) {
	tests := []struct {
		pattern   string
		other     string
		contained bool
	}{
		{"**", "**", true},
		{"**/*", "*/**", true},
		// **/* and ** are equivalent because IDs are required to always have at least one component
		{"**/*", "**", true},
		{"**", "**/*", true},
		{"**/**", "**/**", true},
		{"**/*/**", "**/**", true},
		{"**/*/*", "*/*/**", true},
		{"**/*/*", "**", false},
		{"**", "**/foo", true},
		{"**/foo", "**", false},
		{"**/foo", "**/foo", true},
		{"foo/**", "**/foo", false},
		{"**", "bar/**/foo", true},
		{"**", "*/bar/**/foo", true},
		{"*", "*", true},
		{"*/foo", "*", false},
		{"*", "*/foo", false},
		{"docker/*/mcp/*", "docker/proj1/**", false},
		// docker/x/mcp/y matches the other pattern but not this one.
		{"docker/proj1/**", "docker/*/mcp/*", false},
		{"docker/proj1/**", "docker/**/mcp/**", false},
		{"docker/**", "docker/**/mcp/**", true},
		// a/a/** and a/a/**/** match the same IDs, so each contains the
		// other.
		{"a/a/**", "a/a/**/**", true},
		{"a/a/**/**", "a/a/**", true},
		{"a/a/*", "a/a/**", false},
		{"a/a/*", "a/a/**/**", false},
		{"a/a/**", "a/a/*", true},
		{"a/a/**/**", "a/a/*", true},
	}
	for idx, tc := range tests {
		t.Run(fmt.Sprintf("pattern %d", idx+1), func(t *testing.T) {
			p, err := ParsePattern(tc.pattern)
			require.NoError(t, err)
			other, err := ParsePattern(tc.other)
			require.NoError(t, err)
			assert.Equal(t, tc.contained, p.Contains(other))
		})
	}
}

func TestPatternOverlaps(t *testing.T) {
	tests := []struct {
		pattern  string
		other    string
		overlaps bool
	}{
		{"**", "**", true},
		{"*", "*/foo", false},
		{"*/foo", "*", false},
		{"foo/bar", "foo/baz", false},
		{"foo/*", "foo/bar", true},
		{"foo/**", "**/foo", true},  // both match "foo"
		{"bar/**", "foo/**", false}, // first components conflict
		{"foo/*/baz", "foo/bar/**", true},
		// Overlap without containment in either direction.
		{"docker/*/mcp/*", "docker/proj1/**", true},
		{"foo/foo/foo/**", "foo/foo/**/foo", true},
		{"*/foo/**", "**/bar/*", true},
		{"docker/mcp/auth/**", "foo/bar", false},
		{"a/a/**", "a/a/**/**", true},
		{"a/a/*", "a/a/**", true},
		{"a/a/*", "a/a/**/**", true},
	}
	for idx, tc := range tests {
		t.Run(fmt.Sprintf("pattern %d", idx+1), func(t *testing.T) {
			p, err := ParsePattern(tc.pattern)
			require.NoError(t, err)
			other, err := ParsePattern(tc.other)
			require.NoError(t, err)
			assert.Equal(t, tc.overlaps, p.Overlaps(other))
			assert.Equal(t, tc.overlaps, other.Overlaps(p), "Overlaps must be symmetric")
		})
	}
}

func Test_apply(t *testing.T) {
	type query struct {
		pattern string
		result  string
	}
	tests := []struct {
		pattern string
		queries []query
	}{
		{
			pattern: "foo/bar/**",
			queries: []query{
				{
					pattern: "baz",
					result:  "foo/bar/baz",
				},
				{
					pattern: "**",
					result:  "foo/bar/**",
				},
				{
					pattern: "**/*",
					result:  "foo/bar/**/*",
				},
			},
		},
		{
			pattern: "**/*",
			queries: []query{
				{
					pattern: "baz",
					result:  "baz/*",
				},
				{
					pattern: "bar/baz",
					result:  "bar/baz/*",
				},
				{
					pattern: "**",
					result:  "**/*",
				},
			},
		},
		{
			pattern: "**/**",
			queries: []query{
				{
					pattern: "**/bar",
				},
			},
		},
	}
	for idx, test := range tests {
		t.Run(fmt.Sprintf("%d - %s", idx, test.pattern), func(t *testing.T) {
			for inner, query := range test.queries {
				t.Run(fmt.Sprintf("%d-%d %s %s", idx, inner, test.pattern, query.pattern), func(t *testing.T) {
					result, err := replace1(test.pattern, query.pattern)
					if query.result == "" {
						assert.Error(t, err, fmt.Sprintf("got: %s", result))
						return
					}
					require.NoError(t, err, fmt.Sprintf("query: %s, expected out: %s", query.pattern, query.result))
					assert.Equal(t, query.result, result)
				})
			}
		})
	}
}
