//go:build darwin && !ios && cgo

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

package keychain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAccessControlConvert exercises the Convert() path against a known-good
// flag combination. A successful Convert returns a non-zero CFTypeRef that we
// must release to keep the test leak-free.
func TestAccessControlConvert(t *testing.T) {
	cases := []struct {
		name       string
		protection Accessible
		flags      AccessControlFlags
	}{
		{
			name:       "user presence + after first unlock",
			protection: AccessibleAfterFirstUnlock,
			flags:      AccessControlUserPresence,
		},
		{
			name:       "biometry any + when unlocked",
			protection: AccessibleWhenUnlocked,
			flags:      AccessControlBiometryAny,
		},
		{
			name:       "biometry current set + this device only",
			protection: AccessibleWhenUnlockedThisDeviceOnly,
			flags:      AccessControlBiometryCurrentSet,
		},
		{
			name:       "biometry + passcode fallback combined with OR",
			protection: AccessibleAfterFirstUnlock,
			flags:      AccessControlBiometryAny | AccessControlDevicePasscode | AccessControlOr,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ref, err := AccessControl{Protection: tc.protection, Flags: tc.flags}.Convert()
			require.NoError(t, err)
			require.NotZero(t, ref, "expected non-zero SecAccessControlRef")
			t.Cleanup(func() { Release(ref) })
		})
	}
}

// TestAccessControlConvert_UnknownProtection covers the failure path for an
// unsupported Accessible value (the AccessibleDefault sentinel maps to no
// kSecAttrAccessible* constant).
func TestAccessControlConvert_UnknownProtection(t *testing.T) {
	_, err := AccessControl{Protection: AccessibleDefault, Flags: AccessControlUserPresence}.Convert()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported protection class")
}

// TestSetAccessControl_ReplacesAccessible verifies that calling
// SetAccessControl after SetAccessible drops the Accessible attribute — they
// cannot coexist on the same item.
func TestSetAccessControl_ReplacesAccessible(t *testing.T) {
	item := NewItem()
	item.SetAccessible(AccessibleAfterFirstUnlock)
	require.NotNil(t, item.attr[AccessibleKey], "precondition: Accessible is set")

	item.SetAccessControl(AccessibleAfterFirstUnlock, AccessControlUserPresence)
	_, hasAccessible := item.attr[AccessibleKey]
	assert.False(t, hasAccessible, "Accessible should be removed when AccessControl is set")
	_, hasAccessControl := item.attr[AccessControlKey]
	assert.True(t, hasAccessControl, "AccessControl should be set")
}

// TestSetUseOperationPrompt verifies the round-trip on the attribute map.
func TestSetUseOperationPrompt(t *testing.T) {
	item := NewItem()
	item.SetUseOperationPrompt("Authenticate to read Docker secrets")
	assert.Equal(t, "Authenticate to read Docker secrets", item.attr[UseOperationPromptKey])

	// Empty string clears the attribute (SetString contract).
	item.SetUseOperationPrompt("")
	_, exists := item.attr[UseOperationPromptKey]
	assert.False(t, exists)
}
