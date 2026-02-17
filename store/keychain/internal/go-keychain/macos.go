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

//go:build darwin && !ios
// +build darwin,!ios

package keychain

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"

// AccessibleKey is key for kSecAttrAccessible
var (
	AccessibleKey     = attrKey(C.CFTypeRef(C.kSecAttrAccessible))
	accessibleTypeRef = map[Accessible]C.CFTypeRef{
		AccessibleWhenUnlocked:                   C.CFTypeRef(C.kSecAttrAccessibleWhenUnlocked),
		AccessibleAfterFirstUnlock:               C.CFTypeRef(C.kSecAttrAccessibleAfterFirstUnlock),
		AccessibleAlways:                         C.CFTypeRef(C.kSecAttrAccessibleAlways),
		AccessibleWhenUnlockedThisDeviceOnly:     C.CFTypeRef(C.kSecAttrAccessibleWhenUnlockedThisDeviceOnly),
		AccessibleAfterFirstUnlockThisDeviceOnly: C.CFTypeRef(C.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly),
		AccessibleAccessibleAlwaysThisDeviceOnly: C.CFTypeRef(C.kSecAttrAccessibleAlwaysThisDeviceOnly),

		// Only available in 10.10
		// AccessibleWhenPasscodeSetThisDeviceOnly:  C.CFTypeRef(C.kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly),
	}
)
