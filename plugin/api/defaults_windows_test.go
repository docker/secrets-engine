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

//go:build windows

package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStandalonePluginDir(t *testing.T) {
	assert.Panics(t, func() { _ = StandalonePluginDir() })
}

func TestDesktopPluginDir(t *testing.T) {
	t.Setenv("ProgramFiles", `D:\Program Files`)
	assert.Equal(t, `D:\Program Files\Docker\secrets-engine\desktop-plugins`, DesktopPluginDir())

	t.Setenv("ProgramFiles", "")
	assert.Equal(t, `C:\Program Files\Docker\secrets-engine\desktop-plugins`, DesktopPluginDir())
}
