package examples

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSecretExample(t *testing.T) {
	s := &secret{
		AccessToken:  "access_token",
		RefreshToken: "refresh_token",
	}
	data, err := s.Marshal()
	require.NoError(t, err)
	require.Equal(t, string(data), "access_token:refresh_token")

	anotherSecret := &secret{}
	require.NoError(t, anotherSecret.Unmarshal(data))
	require.EqualValues(t, s, anotherSecret)
}
