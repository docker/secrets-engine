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

//go:build darwin && cgo

package keychain

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/store"
	"github.com/docker/secrets-engine/store/mocks"
)

// TestWithBiometricAuth_Construction asserts that the option is plumbed into
// the keychain store struct without performing any keychain I/O — we cannot
// exercise a Save/Get round-trip in tests because the macOS authentication
// prompt would block waiting for Touch ID input.
func TestWithBiometricAuth_Construction(t *testing.T) {
	factory := func(_ context.Context, _ store.ID) *mocks.MockCredential {
		return &mocks.MockCredential{}
	}

	s, err := New[*mocks.MockCredential](
		"com.test.biometric",
		"sbx-test",
		factory,
		WithDarwinOptions(WithBiometricAuth("Authenticate to read Docker secrets")),
	)
	require.NoError(t, err)

	// Cast back to the concrete type so we can inspect the wired fields.
	// This is test-only inspection; production callers use the store.Store
	// interface.
	ks, ok := s.(*keychainStore[*mocks.MockCredential])
	require.True(t, ok, "New returned an unexpected store type")
	assert.True(t, ks.useBiometricAuth, "biometric auth flag should be set")
	assert.Equal(t, "Authenticate to read Docker secrets", ks.biometricPrompt)
}

// TestWithBiometricAuth_DefaultIsOff covers the unchanged-default invariant:
// constructing a store without WithBiometricAuth must leave the flag off, so
// production callers that have not opted in keep their current behaviour.
func TestWithBiometricAuth_DefaultIsOff(t *testing.T) {
	factory := func(_ context.Context, _ store.ID) *mocks.MockCredential {
		return &mocks.MockCredential{}
	}

	s, err := New[*mocks.MockCredential]("com.test.biometric", "sbx-test", factory)
	require.NoError(t, err)
	ks, ok := s.(*keychainStore[*mocks.MockCredential])
	require.True(t, ok)
	assert.False(t, ks.useBiometricAuth)
	assert.Empty(t, ks.biometricPrompt)
}
