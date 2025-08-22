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
