package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Name(t *testing.T) {
	t.Parallel()
	t.Run("any non-empty string is a valid name", func(t *testing.T) {
		n, err := NewName("foo")
		assert.NoError(t, err)
		assert.Equal(t, "foo", n.String())
	})
	t.Run("no empty string", func(t *testing.T) {
		_, err := NewName("")
		assert.ErrorIs(t, err, ErrEmptyName)
	})
}
