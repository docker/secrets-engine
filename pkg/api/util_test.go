package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParsePluginName(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectedIdx  string
		expectedName string
		expectErr    string
	}{
		{
			name:      "empty",
			expectErr: "invalid plugin name \"\"",
		},
		{
			name:      "no index",
			input:     "pluginname",
			expectErr: "invalid plugin name \"pluginname\"",
		},
		{
			name:         "valid index and name",
			input:        "10-plugin-name",
			expectedIdx:  "10",
			expectedName: "plugin-name",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idx, name, err := ParsePluginName(tt.input)
			if tt.expectErr != "" {
				assert.ErrorContains(t, err, tt.expectErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedIdx, idx)
			assert.Equal(t, tt.expectedName, name)
		})
	}
}

func TestCheckPluginIndex(t *testing.T) {
	tests := []struct {
		name  string
		index string
		err   error
	}{
		{
			name:  "valid index",
			index: "10",
		},
		{
			name:  "invalid index - too short",
			index: "1",
			err:   &ErrInvalidPluginIndex{Actual: "1", Msg: "must be two digits"},
		},
		{
			name:  "invalid index - too long",
			index: "100",
			err:   &ErrInvalidPluginIndex{Actual: "100", Msg: "must be two digits"},
		},
		{
			name:  "invalid index - non-digit characters",
			index: "1a",
			err:   &ErrInvalidPluginIndex{Actual: "1a", Msg: "pattern does not match [0-9][0-9]"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckPluginIndex(tt.index)
			if tt.err != nil {
				assert.ErrorIs(t, err, tt.err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
