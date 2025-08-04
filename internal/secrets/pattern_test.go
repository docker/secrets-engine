package secrets

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParsePattern(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		mustError bool
	}{
		{"valid pattern with single component", "foo", false},
		{"valid pattern with multiple components", "foo/bar/baz", false},
		{"valid pattern only with asterisk", "*", false},
		{"valid pattern only with double asterisk", "**", false},
		{"valid pattern starting with asterisk", "*/bar", false},
		{"valid pattern ending with asterisk", "foo/*/baz", false},
		{"valid pattern starting with double asterisk", "**/bar", false},
		{"valid pattern ending with double asterisk", "foo/**/baz", false},
		{"valid pattern with mix of components and wildcards", "foo/*/baz/**/*", false},
		{"invalid pattern with mix of asterisks and allowed characters v1", "*a*", true},
		{"invalid pattern with mix of asterisks and allowed characters v2", "*a", true},
		{"invalid pattern with leading slash", "/foo/bar", true},
		{"invalid pattern with trailing slash", "foo/bar/", true},
		{"invalid pattern with empty component", "foo//bar", true},
		{"invalid empty pattern", "", true},
		{"invalid pattern only with slash", "/", true},
		{"invalid pattern with components and a mix of asterisks and allowed characters", "foo/*a*/baz", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParsePattern(tc.input)
			if tc.mustError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestParsePatternNew(t *testing.T) {
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
			_, err := ParsePatternNew(tc.input)
			assert.ErrorIs(t, err, tc.expected)
		})
	}
}
