package secrets

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseID(t *testing.T) {
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
			_, err := ParseID(tc.input)
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
		pattern   Pattern
		matches   []string
		noMatches []string
	}{
		{
			pattern: "**",
			matches: []string{"foo", "foo/bar", "foo/bar/baz"},
		},
		{
			pattern:   "foo/bar",
			matches:   []string{"foo/bar"},
			noMatches: []string{"foo/bar/baz", "foo"},
		},
		{
			pattern:   "foo/*",
			matches:   []string{"foo/bar"},
			noMatches: []string{"foo/bar/baz", "foo"},
		},
		{
			pattern:   "*/bar",
			matches:   []string{"foo/bar"},
			noMatches: []string{"foo/bar/baz", "foo"},
		},
		{
			pattern:   "foo/**/baz",
			matches:   []string{"foo/bar/baz", "foo/baz", "foo/bar/something/baz"},
			noMatches: []string{"foo/bar", "foo/bar/baz/qux"},
		},
	}
	for _, tc := range tests {
		t.Run(string(tc.pattern), func(t *testing.T) {
			for _, m := range tc.matches {
				id, err := ParseID(m)
				assert.NoError(t, err)
				assert.True(t, id.Match(tc.pattern), "expected %q to match %q", m, tc.pattern)
			}
			for _, nm := range tc.noMatches {
				id, err := ParseID(nm)
				assert.NoError(t, err)
				assert.False(t, id.Match(tc.pattern), "expected %q to not match %q", nm, tc.pattern)
			}
		})
	}
}
