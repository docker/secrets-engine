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

// Package store holds aliases of the types and helpers that moved to
// github.com/docker/secrets-engine/secrets.
//
// Deprecated: Use github.com/docker/secrets-engine/secrets instead. The store
// backends in the keychain and posixage subpackages are not deprecated.
package store

import "github.com/docker/secrets-engine/secrets"

// Deprecated: Use [secrets.ID] instead.
//
//go:fix inline
type ID = secrets.ID

// Deprecated: Use [secrets.Pattern] instead.
//
//go:fix inline
type Pattern = secrets.Pattern

// Deprecated: Use [secrets.Secret] instead.
//
//go:fix inline
type Secret = secrets.Secret

// Deprecated: Use [secrets.Store] instead.
//
//go:fix inline
type Store = secrets.Store

// Deprecated: Use [secrets.Factory] instead.
//
//go:fix inline
type Factory[T secrets.Secret] = secrets.Factory[T]

// Deprecated: Use [secrets.ParseID] instead.
//
//go:fix inline
func ParseID(s string) (secrets.ID, error) {
	return secrets.ParseID(s)
}

// Deprecated: Use [secrets.MustParseID] instead.
//
//go:fix inline
func MustParseID(s string) secrets.ID {
	return secrets.MustParseID(s)
}

// Deprecated: Use [secrets.ParsePattern] instead.
//
//go:fix inline
func ParsePattern(s string) (secrets.Pattern, error) {
	return secrets.ParsePattern(s)
}

// Deprecated: Use [secrets.MustParsePattern] instead.
//
//go:fix inline
func MustParsePattern(s string) secrets.Pattern {
	return secrets.MustParsePattern(s)
}
