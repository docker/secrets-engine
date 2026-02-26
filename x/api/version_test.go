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
