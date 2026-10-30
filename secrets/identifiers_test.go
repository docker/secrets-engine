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
	"errors"
	"testing"
)

func TestParseIDNew(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected error
	}{
		{"valid name with dash", "my-secretA9", nil},
		{"valid name with dot", "my.secretA9", nil},
		{"valid name with slash", "my/secret", nil},
		{"valid name with underscore", "my_secretA9", nil},
		{"valid name with colon", "127.0.0.1:8080", nil},
		{"invalid name with trailing slash", "my/secret/", ErrInvalidID{"my/secret/"}},
		{"invalid name with leading slash", "/my/secret", ErrInvalidID{"/my/secret"}},
		{"invalid name with empty component", "my//secret", ErrInvalidID{"my//secret"}},
		{"invalid name with space", "my secret", ErrInvalidID{"my secret"}},
		{"invalid name with hashtag", "my#secret", ErrInvalidID{"my#secret"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseID(tc.input)
			if !errors.Is(err, tc.expected) {
				t.Errorf("ParseID(%q) error = %v, want %v", tc.input, err, tc.expected)
			}
		})
	}
}

func TestIDComparable(t *testing.T) {
	a := MustParseID("foo")
	b := MustParseID("foo")
	if a != b {
		t.Errorf("%v != %v", a, b)
	}
	myMap := map[ID]string{}
	bar := "bar"
	myMap[MustParseID("foo")] = bar
	if myMap[a] != bar || myMap[b] != bar {
		t.Errorf("map lookup = %q, %q, want %q", myMap[a], myMap[b], bar)
	}
}

func TestMatchNew(t *testing.T) {
	tests := []struct {
		pattern  string
		ids      []string
		expected bool
	}{
		{
			pattern:  "*/**/*",
			ids:      []string{"foo/bar", "foo/bar/baz"},
			expected: true,
		},
		{
			pattern:  "**",
			ids:      []string{"foo", "foo/bar", "foo/bar/baz"},
			expected: true,
		},
		{
			pattern:  "foo/bar",
			ids:      []string{"foo/bar/baz", "foo"},
			expected: false,
		},
		{
			pattern:  "foo/*",
			ids:      []string{"foo/bar"},
			expected: true,
		},
		{
			pattern:  "foo/*",
			ids:      []string{"foo/bar/baz", "foo"},
			expected: false,
		},
		{
			pattern:  "*/bar",
			ids:      []string{"foo/bar"},
			expected: true,
		},
		{
			pattern:  "*/bar",
			ids:      []string{"foo/bar/baz", "foo"},
			expected: false,
		},
		{
			pattern:  "foo/**/baz",
			ids:      []string{"foo/bar/baz", "foo/baz", "foo/bar/something/baz"},
			expected: true,
		},
		{
			pattern:  "foo/**/baz",
			ids:      []string{"foo/bar", "foo/bar/baz/qux"},
			expected: false,
		},
		{
			pattern:  "com.test.test/**",
			ids:      []string{"com.test.test/test/bob", "com.test.test/test/alice"},
			expected: true,
		},
		{
			pattern:  "foo/127.0.0.1:8080/**",
			ids:      []string{"foo/127.0.0.1:8080/bob", "foo/127.0.0.1:8080/jeff/test"},
			expected: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.pattern, func(t *testing.T) {
			for _, m := range tc.ids {
				id, err := ParseID(m)
				if err != nil {
					t.Fatalf("ParseID(%q): %v", m, err)
				}
				pattern, err := ParsePattern(tc.pattern)
				if err != nil {
					t.Fatalf("ParsePattern(%q): %v", tc.pattern, err)
				}
				if got := id.Match(pattern); got != tc.expected {
					t.Errorf("unexpected match for id `%q` to and pattern `%q`: got %v", m, tc.pattern, got)
				}
			}
		})
	}
}
