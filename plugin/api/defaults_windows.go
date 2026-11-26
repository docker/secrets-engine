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
	"os"
	"path/filepath"
)

// StandalonePluginDir panics: the standalone Secrets Engine has no plugin
// directory on Windows.
func StandalonePluginDir() string {
	panic("api: the standalone Secrets Engine has no plugin directory on Windows")
}

// DesktopPluginDir returns the plugin directory of Docker Desktop's Secrets
// Engine. The directory must be owned by Administrators and world-readable.
func DesktopPluginDir() string {
	base := os.Getenv("ProgramFiles")
	if base == "" {
		base = `C:\Program Files`
	}
	return filepath.Join(base, "Docker", "secrets-engine", "desktop-plugins")
}
