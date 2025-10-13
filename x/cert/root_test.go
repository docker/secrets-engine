package cert

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCert(t *testing.T) {
	rootCA, err := NewRootCA()
	require.NoError(t, err)

	another, err := NewRootCA()
	require.NoError(t, err)
	require.Equal(t, rootCA, another)
}
