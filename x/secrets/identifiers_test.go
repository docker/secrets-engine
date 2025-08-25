package secrets

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
		{"invalid name with trailing slash", "my/secret/", ErrInvalidID{"my/secret/"}},
		{"invalid name with leading slash", "/my/secret", ErrInvalidID{"/my/secret"}},
		{"invalid name with empty component", "my//secret", ErrInvalidID{"my//secret"}},
		{"invalid name with colon", "my:secret", ErrInvalidID{"my:secret"}},
		{"invalid name with space", "my secret", ErrInvalidID{"my secret"}},
		{"invalid name with hashtag", "my#secret", ErrInvalidID{"my#secret"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseID(tc.input)
			assert.ErrorIs(t, err, tc.expected)
		})
	}
}

func TestIDComparable(t *testing.T) {
	a := MustParseID("foo")
	b := MustParseID("foo")
	assert.Equal(t, a, b)
	myMap := map[ID]string{}
	bar := "bar"
	myMap[MustParseID("foo")] = bar
	assert.Equal(t, bar, myMap[a])
	assert.Equal(t, bar, myMap[b])
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
	}
	for _, tc := range tests {
		t.Run(tc.pattern, func(t *testing.T) {
			for _, m := range tc.ids {
				id, err := ParseID(m)
				assert.NoError(t, err)
				pattern, err := ParsePattern(tc.pattern)
				assert.NoError(t, err)
				assert.Equalf(t, tc.expected, id.Match(pattern), "unexpected match for id `%q` to and pattern `%q`", m, tc.pattern)
			}
		})
	}
}
