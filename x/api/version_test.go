package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Version(t *testing.T) {
	t.Parallel()
	t.Run("any semver string is a valid version", func(t *testing.T) {
		v, err := NewVersion("v1.0")
		assert.NoError(t, err)
		assert.Equal(t, "v1.0", v.String())
	})
	t.Run("no v prefix", func(t *testing.T) {
		_, err := NewVersion("1.0.0")
		assert.ErrorIs(t, err, ErrVPrefix)
	})
	t.Run("no empty string", func(t *testing.T) {
		_, err := NewVersion("")
		assert.ErrorIs(t, err, ErrEmptyVersion)
	})
}
