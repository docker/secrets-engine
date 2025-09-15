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
	t.Run("valid value", func(t *testing.T) {
		b := PluginBehaviour{Value: "foo"}
		s, err := b.ToString()
		require.NoError(t, err)
		r, err := ParsePluginBehaviour(s)
		require.NoError(t, err)
		assert.Equal(t, b, r)
	})
}
