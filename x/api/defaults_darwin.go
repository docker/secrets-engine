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

//go:build darwin

package api

import (
	"os"
	"path/filepath"
)

// StandaloneSocketPath returns the standalone Secrets Engine's listening socket
// path. It uses the user's cache directory, falling back to the temporary
// directory when the cache directory cannot be determined.
func StandaloneSocketPath() string {
	if dir, err := os.UserCacheDir(); err == nil {
		return filepath.Join(dir, "docker-secrets-engine", "daemon.sock")
	}
	return filepath.Join(os.TempDir(), "docker-secrets-engine", "daemon.sock")
}

// DaemonSocketPath returns the standalone Secrets Engine's listening socket path.
//
// Deprecated: Use [StandaloneSocketPath] instead.
func DaemonSocketPath() string {
	return StandaloneSocketPath()
}
