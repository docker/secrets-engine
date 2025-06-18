package adaptation

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mockPluginNameWithLength(n int) string {
	var sb strings.Builder
	sb.Grow(n)
	for i := 0; i < n; i++ {
		if i%2 == 0 {
			sb.WriteByte('a')
		} else {
			sb.WriteByte('b')
		}
	}
	return sb.String()
}

func TestPluginConfigFromEngine_ToString(t *testing.T) {
	in := PluginConfigFromEngine{
		Name:                mockPluginNameWithLength(500),
		RegistrationTimeout: 27 * time.Nanosecond,
		Fd:                  10,
	}
	out, err := in.ToString()
	assert.NoError(t, err)
	// This is coming from here: https://superuser.com/questions/1070272/why-does-windows-have-a-limit-on-environment-variables-at-all
	// -> we verify that a plugin name of 500 characters is still within the limit
	assert.LessOrEqual(t, len(out), 2048)
	restored, err := NewPluginConfigFromEngineFromString(out)
	assert.NoError(t, err)
	assert.Equal(t, in, *restored)
}

func TestNewPluginConfigFromEngineFromString(t *testing.T) {
	tests := []struct {
		name string
		in   PluginConfigFromEngine
		err  string
	}{
		{
			name: "name is empty",
			err:  "name is required",
		},
		{
			name: "registration timeout is zero",
			in: PluginConfigFromEngine{
				Name: "test-plugin",
			},
			err: "registration timeout is required",
		},
		{
			name: "fd is nonsense",
			in: PluginConfigFromEngine{
				Name:                "test-plugin",
				RegistrationTimeout: 10 * time.Second,
				Fd:                  2,
			},
			err: "invalid file descriptor",
		},
		{
			name: "valid config",
			in: PluginConfigFromEngine{
				Name:                "test-plugin",
				RegistrationTimeout: 10 * time.Second,
				Fd:                  10,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := tt.in.ToString()
			require.NoError(t, err)
			_, err = NewPluginConfigFromEngineFromString(out)
			if tt.err != "" {
				assert.ErrorContains(t, err, tt.err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
