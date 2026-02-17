// Copyright 2025-2026 Docker, Inc.
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

package ipc

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPluginConfigFromEngine_ToString(t *testing.T) {
	in := PluginConfigFromEngine{
		Name:                strings.Repeat("ab", 250), // 500 characters
		RegistrationTimeout: 27 * time.Nanosecond,
		Custom:              FakeTestCustom(10),
	}
	out, err := in.ToString()
	assert.NoError(t, err)
	// This is coming from here: https://superuser.com/questions/1070272/why-does-windows-have-a-limit-on-environment-variables-at-all
	// -> we verify that a plugin name of 500 characters is still within the limit
	assert.LessOrEqual(t, len(out), 2048)
	restored, err := NewPluginConfigFromEngineEnv(out)
	assert.NoError(t, err)
	assert.Equal(t, in, *restored)
}

func TestNewPluginConfigFromEngineFromString(t *testing.T) {
	t.Parallel()
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
				Custom:              FakeTestCustom(2),
			},
			err: "invalid file descriptor",
		},
		{
			name: "valid config",
			in: PluginConfigFromEngine{
				Name:                "test-plugin",
				RegistrationTimeout: 10 * time.Second,
				Custom:              FakeTestCustom(10),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := tt.in.ToString()
			require.NoError(t, err)
			_, err = NewPluginConfigFromEngineEnv(out)
			if tt.err != "" {
				assert.ErrorContains(t, err, tt.err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
