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

package store

import (
	"errors"

	"github.com/docker/secrets-engine/x/secrets"
)

var ErrCredentialNotFound = secrets.ErrNotFound

// ErrEmptySecret is returned by Save and Upsert when the secret's value is
// empty. The macOS Keychain ignores an empty value on update and keeps the old
// one, so every store refuses it instead of reporting a success that changed
// nothing.
var ErrEmptySecret = errors.New("secret value must not be empty")
