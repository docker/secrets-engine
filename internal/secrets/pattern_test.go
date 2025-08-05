package secrets

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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
			_, err := ParsePattern(tc.input)
			assert.ErrorIs(t, err, tc.expected)
		})
	}
}

func TestPatternParts(t *testing.T) {
	tests := []struct {
		desc     string
		pattern  string
		expected []patternPart
	}{
		{
			desc:    "singular part",
			pattern: "foo",
			expected: []patternPart{
				{
					value:       "foo",
					patternType: ConcretePatternPartType,
				},
			},
		},
		{
			desc:    "multiple parts",
			pattern: "foo/baz",
			expected: []patternPart{
				{
					value:       "foo",
					patternType: ConcretePatternPartType,
				},
				{
					value:       "baz",
					patternType: ConcretePatternPartType,
				},
			},
		},
		{
			desc:    "multiple parts with recursive any",
			pattern: "foo/**/baz",
			expected: []patternPart{
				{
					value:       "foo",
					patternType: ConcretePatternPartType,
				},
				{
					value:       "**",
					patternType: AnyRecursivePatternPartType,
				},
				{
					value:       "baz",
					patternType: ConcretePatternPartType,
				},
			},
		},
		{
			desc:    "multiple parts with any",
			pattern: "foo/*/baz/*",
			expected: []patternPart{
				{
					value:       "foo",
					patternType: ConcretePatternPartType,
				},
				{
					value:       "*",
					patternType: AnyPatternPartType,
				},
				{
					value:       "baz",
					patternType: ConcretePatternPartType,
				},
				{
					value:       "*",
					patternType: AnyPatternPartType,
				},
			},
		},
		{
			desc:    "multiple parts with both recursive any and any",
			pattern: "foo/**/baz/*",
			expected: []patternPart{
				{
					value:       "foo",
					patternType: ConcretePatternPartType,
				},
				{
					value:       "**",
					patternType: AnyRecursivePatternPartType,
				},
				{
					value:       "baz",
					patternType: ConcretePatternPartType,
				},
				{
					value:       "*",
					patternType: AnyPatternPartType,
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			var parts []patternPart
			for part := range (&pattern{tc.pattern}).Parts() {
				parts = append(parts, *(part.(*patternPart)))
			}
			assert.Len(t, parts, len(tc.expected))
			assert.EqualValues(t, tc.expected, parts)
		})
	}
}
