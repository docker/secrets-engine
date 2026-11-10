package secrets

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScope(t *testing.T) {
	type query struct {
		input string
		fwd   string
	}
	tests := []struct {
		scope   string
		queries []query
	}{
		{
			scope: "docker/*/mcp/*",
			queries: []query{
				{
					input: "docker",
				},
				{
					input: "docker/proj1/mcp/foo",
					fwd:   "proj1/foo",
				},
				{
					input: "docker/proj1/mcp/**",
					fwd:   "proj1/*",
				},
				{
					input: "docker/*/mcp/*",
					fwd:   "*/*",
				},
				{
					input: "**",
					fwd:   "*/*",
				},
				{
					input: "docker/proj1/**",
					fwd:   "proj1/*",
				},
				{
					input: "docker/proj1/**/bar",
					fwd:   "proj1/bar",
				},
				{
					input: "docker/proj1/**/bar/foo",
				},
				{
					input: "docker/proj1/mcp/**",
					fwd:   "proj1/*",
				},
			},
		},
		{
			scope: "docker/**/mcp/*",
			queries: []query{
				{
					input: "docker",
				},
				{
					input: "docker/proj1/mcp/foo",
					fwd:   "proj1/foo",
				},
				{
					input: "docker/proj1/mcp",
				},
				{
					input: "docker/mcp/foo",
					fwd:   "foo",
				},
			},
		},
		{
			scope: "docker/*/mcp/**",
			queries: []query{
				{
					input: "docker/proj1/**",
					fwd:   "proj1/**",
				},
				{
					input: "docker/proj1/**/bar",
					fwd:   "proj1/**/bar",
				},
			},
		},
		{
			scope: "a/b/*",
			queries: []query{
				{
					input: "**/c",
					fwd:   "c",
				},
			},
		},
		{
			scope: "b/*",
			queries: []query{
				{
					input: "**",
					fwd:   "*",
				},
				{
					input: "**/b",
					fwd:   "b",
				},
			},
		},
		{
			scope: "*",
			queries: []query{
				{
					input: "**",
					fwd:   "*",
				},
				{
					input: "*",
					fwd:   "*",
				},
				{
					input: "a",
					fwd:   "a",
				},

				{
					input: "a/b",
				},
			},
		},
		{
			scope: "baz",
			queries: []query{
				{
					input: "**",
					fwd:   "**",
				},
				{
					input: "**/baz",
				},
				{
					input: "foo",
				},
				{
					input: "**/bar",
				},
			},
		},
		{
			scope: "**/baz",
			queries: []query{
				{
					input: "**/baz",
					fwd:   "**",
				},
				{
					input: "**",
					fwd:   "**",
				},
				{
					input: "**/foo",
				},
			},
		},
		{
			scope: "**/*",
			queries: []query{
				{
					input: "**",
					fwd:   "**/*",
				},
				{
					input: "b/*",
					fwd:   "b/*",
				},
			},
		},
		{
			scope: "**/*/**/*",
			queries: []query{
				{
					input: "**",
					fwd:   "**/*/**/*",
				},
			},
		},
		{
			scope: "**/*/bar/*",
			queries: []query{
				{
					input: "**",
					fwd:   "**/*/*",
				},
			},
		},
		{
			scope: "bar/**/baz",
			queries: []query{
				{
					input: "**/baz",
					fwd:   "**",
				},
				{
					input: "**",
					fwd:   "**",
				},
				{
					input: "bar/**/baz",
					fwd:   "**",
				},
			},
		},
		{
			scope: "**/bar/**",
			queries: []query{
				{
					input: "**/baz",
					fwd:   "**/baz",
				},
				{
					input: "**/*/bar",
					fwd:   "**/*/bar",
				},
			},
		},
		{
			scope: "docker/*/mcp/**/baz",
			queries: []query{
				{
					input: "docker/proj1/**",
					fwd:   "proj1/**",
				},
				{
					input: "docker/proj1/**/bar",
				},
				{
					input: "docker/proj1/**/baz",
					fwd:   "proj1/**",
				},
			},
		},
		{
			scope: "docker/*/mcp/**/*",
			queries: []query{
				{
					input: "docker/proj1/**",
					fwd:   "proj1/**/*",
				},
				{
					input: "docker/proj1/**/*",
					fwd:   "proj1/**/*",
				},
				{
					input: "docker/proj1/**/bar",
					fwd:   "proj1/**/bar",
				},
			},
		},
		{
			scope: "docker/*/mcp/**/bar/**",
			queries: []query{
				{
					input: "docker/proj1/**",
					fwd:   "proj1/**",
				},
				{
					input: "docker/proj1/**/*",
					fwd:   "proj1/**/*",
				},
				{
					input: "docker/proj1/**/*/bar",
					fwd:   "proj1/**/*/bar",
				},
				{
					input: "docker/proj1/**/baz",
					fwd:   "proj1/**/baz",
				},
				{
					input: "docker/proj1/**/bar",
					fwd:   "proj1/**/bar",
				},
				{
					input: "docker/proj1/**/*/*",
					fwd:   "proj1/**/*/*",
				},
			},
		},
	}
	for idx, test := range tests {
		t.Run(fmt.Sprintf("%d - %s", idx, test.scope), func(t *testing.T) {
			s, err := NewDynamicScope(test.scope)
			assert.NoError(t, err)
			for inner, query := range test.queries {
				t.Run(fmt.Sprintf("%d-%d %s %s", idx, inner, test.scope, query.input), func(t *testing.T) {
					fwd, ok := s.Forward(MustParsePattern(query.input))
					if query.fwd == "" {
						assert.False(t, ok)
						return
					}
					require.True(t, ok, fmt.Sprintf("query: %s, expected out: %s", query.input, query.fwd))
					assert.Equal(t, query.fwd, fwd.String())
				})
			}
		})
	}
}
