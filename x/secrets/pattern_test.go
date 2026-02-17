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

func TestPatternIncludes(t *testing.T) {
	tests := []struct {
		pattern         string
		other           string
		otherIsIncluded bool
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
		{"docker/proj1/**", "docker/*/mcp/*", true},
		{"docker/proj1/**", "docker/**/mcp/**", false},
		{"docker/**", "docker/**/mcp/**", true},
	}
	for idx, tc := range tests {
		t.Run(fmt.Sprintf("pattern %d", idx+1), func(t *testing.T) {
			p, err := ParsePattern(tc.pattern)
			require.NoError(t, err)
			other, err := ParsePattern(tc.other)
			require.NoError(t, err)
			assert.Equal(t, tc.otherIsIncluded, p.Includes(other))
		})
	}
}

func Test_Filter(t *testing.T) {
	tests := []struct {
		filter string
		other  string
		result string
	}{
		{
			filter: "docker/mcp/auth/**",
			other:  "**",
			result: "docker/mcp/auth/**",
		},
		{
			filter: "**",
			other:  "**",
			result: "**",
		},
		{
			filter: "docker/mcp/auth/**",
			other:  "docker/mcp/auth/foo/bar/*",
			result: "docker/mcp/auth/foo/bar/*",
		},
		{
			filter: "**/mcp/auth/**",
			other:  "docker/*/auth/foo/bar/*",
			result: "docker/*/auth/foo/bar/*",
		},
		{
			filter: "**/mcp/auth/**",
			other:  "*/*/auth/foo/bar/*",
			result: "*/*/auth/foo/bar/*",
		},
		{
			filter: "docker/mcp/auth/**",
			other:  "foo/bar",
		},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("f: %s in: %s", tc.filter, tc.other), func(t *testing.T) {
			filter := MustParsePattern(tc.filter)
			other := MustParsePattern(tc.other)
			result, ok := Filter(filter, other)
			if tc.result == "" {
				assert.False(t, ok)
				return
			}
			require.True(t, ok)
			assert.Equal(t, tc.result, result.String())
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
