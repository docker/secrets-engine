package secrets

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewID(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		mustError bool
	}{
		{"valid name with dash", "my-secretA9", false},
		{"valid name with dot", "my.secretA9", false},
		{"valid name with slash", "my/secret", false},
		{"valid name with underscore", "my_secretA9", false},
		{"invalid name with trailing slash", "my/secret/", true},
		{"invalid name with leading slash", "/my/secret", true},
		{"invalid name with empty component", "my//secret", true},
		{"invalid name with colon", "my:secret", true},
		{"invalid name with space", "my secret", true},
		{"invalid name with hashtag", "my#secret", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewID(tc.input)
			if tc.mustError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMatch(t *testing.T) {
	tests := []struct {
		pattern  string
		ids      []string
		expected bool
	}{
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
	}
	for _, tc := range tests {
		t.Run(string(tc.pattern), func(t *testing.T) {
			t.Logf("ids: %+v", tc.ids)
			for _, m := range tc.ids {
				id, err := NewID(m)
				assert.NoError(t, err)
				pattern, err := ParsePattern(tc.pattern)
				assert.NoError(t, err)
				assert.Equalf(t, tc.expected, id.Match(pattern), "unexpected match for id `%q` to and pattern `%q`", m, tc.pattern)
			}
		})
	}
}
