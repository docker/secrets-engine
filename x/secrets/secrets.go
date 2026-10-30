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

// Package secrets aliases github.com/docker/secrets-engine/secrets.
//
// Deprecated: Use github.com/docker/secrets-engine/secrets instead. This
// package will be removed after its last tag.
package secrets

import "github.com/docker/secrets-engine/secrets"

var (
	// Deprecated: Use [secrets.ErrNotFound] instead.
	ErrNotFound = secrets.ErrNotFound
	// Deprecated: Use [secrets.ErrAccessDenied] instead.
	ErrAccessDenied = secrets.ErrAccessDenied
	// Deprecated: Use [secrets.ErrEmptySecret] instead.
	ErrEmptySecret = secrets.ErrEmptySecret
	// Deprecated: Use [secrets.ErrInvalidPattern] instead.
	ErrInvalidPattern = secrets.ErrInvalidPattern
)

// Deprecated: Use [secrets.ErrInvalidID] instead.
//
//go:fix inline
type ErrInvalidID = secrets.ErrInvalidID

// Deprecated: Use [secrets.ID] instead.
//
//go:fix inline
type ID = secrets.ID

// Deprecated: Use [secrets.Pattern] instead.
//
//go:fix inline
type Pattern = secrets.Pattern

// Deprecated: Use [secrets.Envelope] instead.
//
//go:fix inline
type Envelope = secrets.Envelope

// Deprecated: Use [secrets.Resolver] instead.
//
//go:fix inline
type Resolver = secrets.Resolver

// Deprecated: Use [secrets.AuthorizeResponse] instead.
//
//go:fix inline
type AuthorizeResponse = secrets.AuthorizeResponse

// Deprecated: Use [secrets.Authorizer] instead.
//
//go:fix inline
type Authorizer = secrets.Authorizer

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

// Deprecated: Use [secrets.Minimize] instead.
//
//go:fix inline
func Minimize(patterns []secrets.Pattern) []secrets.Pattern {
	return secrets.Minimize(patterns)
}
