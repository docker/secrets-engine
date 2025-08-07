package testdummy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_dummyPluginBehaviour(t *testing.T) {
	t.Parallel()
	t.Run("no dashes in value", func(t *testing.T) {
		b := PluginBehaviour{Value: "in-valid"}
		_, err := b.ToString()
		assert.Error(t, err)
	})
	t.Run("with exit behaviour", func(t *testing.T) {
		b := PluginBehaviour{
			Value:          "foo",
			CrashBehaviour: &CrashBehaviour{OnNthSecretRequest: 1, ExitCode: 0},
		}
		s, err := b.ToString()
		require.NoError(t, err)
		r, err := ParsePluginBehaviour(s)
		require.NoError(t, err)
		assert.Equal(t, b, r)
	})
	t.Run("without exit behaviour", func(t *testing.T) {
		b := PluginBehaviour{Value: "foo"}
		s, err := b.ToString()
		require.NoError(t, err)
		r, err := ParsePluginBehaviour(s)
		require.NoError(t, err)
		assert.Equal(t, b, r)
	})
}
