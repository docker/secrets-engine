package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_cutVersionExtra(t *testing.T) {
	t.Parallel()
	tests := []struct {
		versionBefore string
		versionAfter  string
		metadataAfter string
	}{
		{
			versionBefore: "v0.1.0",
			versionAfter:  "v0.1.0",
		},
		{
			versionBefore: "v0.1.0-pre+meta",
			versionAfter:  "v0.1.0",
			metadataAfter: "-pre+meta",
		},
		{
			versionBefore: "v0.1.0+meta",
			versionAfter:  "v0.1.0",
			metadataAfter: "+meta",
		},
	}
	for _, test := range tests {
		t.Run(test.versionBefore, func(t *testing.T) {
			v, extra := cutVersionExtra(test.versionBefore)
			assert.Equal(t, test.versionAfter, v)
			assert.Equal(t, test.metadataAfter, extra)
		})
	}
}

func Test_futureVersion(t *testing.T) {
	t.Parallel()
	t.Run("non canonical version", func(t *testing.T) {
		_, err := newFutureVersions("v0.0.0.1")
		assert.Error(t, err)
	})
	tests := []struct {
		current string
		result  *futureVersions
	}{
		{
			current: "v0.0.1",
			result: &futureVersions{
				major: "v1.0.0",
				minor: "v0.1.0",
				patch: "v0.0.2",
			},
		},
		{
			current: "v0.1.1",
			result: &futureVersions{
				major: "v1.0.0",
				minor: "v0.2.0",
				patch: "v0.1.2",
			},
		},
		{
			current: "v1.1.1",
			result: &futureVersions{
				major: "v2.0.0",
				minor: "v1.2.0",
				patch: "v1.1.2",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.current, func(t *testing.T) {
			d, err := newFutureVersions(test.current)
			require.NoError(t, err)
			assert.Equal(t, *test.result, *d)
		})
	}
}
