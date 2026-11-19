// Copyright 2026 Docker, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package plugin

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/plugin"
)

func TestPluginVersion(t *testing.T) {
	for _, override := range []string{
		"v1.2.3",
		"v0.0.0-20261119125715-1e09e23a5625",
		"v0.1.1-0.20261119125715-1e09e23a5625+dirty",
	} {
		v, err := pluginVersion(override)
		require.NoError(t, err, override)
		assert.Equal(t, override, v.String())
	}

	_, err := pluginVersion("1.2.3")
	require.Error(t, err)

	for _, unset := range []string{"", "dev"} {
		v, err := pluginVersion(unset)
		require.NoError(t, err, unset)
		assert.Equal(t, "v0.0.0-not-set", v.String())
	}
}

func TestParseSecretsDotenv(t *testing.T) {
	got, err := parseSecrets([]byte("# comment\nDB_TOKEN=hunter2\nAPI_KEY=\"quoted value\"\n"))
	require.NoError(t, err)

	require.Len(t, got, 2)
	assert.Equal(t, []byte("hunter2"), got[plugin.MustParseID("DB_TOKEN")])
	assert.Equal(t, []byte("quoted value"), got[plugin.MustParseID("API_KEY")])
}

func TestParseSecretsNoVariableSubstitution(t *testing.T) {
	got, err := parseSecrets([]byte("DB_PASS=token$SUFFIX\nLITERAL='a$b${c}'\nDQ=\"x$y\"\n"))
	require.NoError(t, err)

	assert.Equal(t, []byte("token$SUFFIX"), got[plugin.MustParseID("DB_PASS")])
	assert.Equal(t, []byte("a$b${c}"), got[plugin.MustParseID("LITERAL")])
	assert.Equal(t, []byte("x$y"), got[plugin.MustParseID("DQ")])
}

func TestParseSecretsInvalidKey(t *testing.T) {
	_, err := parseSecrets([]byte("bad key=value\n"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid secret key")
}

func TestParseSecretsEmpty(t *testing.T) {
	for _, raw := range [][]byte{nil, []byte("   \n\t"), []byte("# only a comment\n")} {
		_, err := parseSecrets(raw)
		require.Error(t, err)
	}
}

func TestResolverGetSecretsMatchAll(t *testing.T) {
	r := newTestResolver(t)

	got, err := r.GetSecrets(context.Background(), plugin.MustParsePattern("**"))
	require.NoError(t, err)
	assert.Len(t, got, 2)
}

func TestResolverGetSecretsFiltered(t *testing.T) {
	r := newTestResolver(t)

	got, err := r.GetSecrets(context.Background(), plugin.MustParsePattern("DB_TOKEN"))
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "DB_TOKEN", got[0].ID.String())
	assert.Equal(t, []byte("hunter2"), got[0].Value)
}

func TestResolverGetSecretsNotFound(t *testing.T) {
	r := newTestResolver(t)

	_, err := r.GetSecrets(context.Background(), plugin.MustParsePattern("MISSING"))
	require.ErrorIs(t, err, plugin.ErrNotFound)
}

func newTestResolver(t *testing.T) *resolver {
	t.Helper()
	secrets, err := parseSecrets([]byte("DB_TOKEN=hunter2\nAPI_KEY=abc\n"))
	require.NoError(t, err)
	return &resolver{secrets: secrets}
}
