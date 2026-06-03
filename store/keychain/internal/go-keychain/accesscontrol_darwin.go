//go:build darwin && !ios
// +build darwin,!ios

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

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"

import (
	"errors"
	"fmt"
)

// AccessControlFlags is a bit set matching Apple's SecAccessControlCreateFlags.
// Combine flags with the bitwise OR operator. The "Or" / "And" flags select
// how multiple authentication requirements compose; when omitted, Apple
// defaults to "Or" (any of the listed factors satisfies the prompt).
//
// See https://developer.apple.com/documentation/security/secaccesscontrolcreateflags
type AccessControlFlags uint64

const (
	// AccessControlUserPresence prompts the user with Touch ID, Face ID, or
	// passcode as a fallback. Equivalent to kSecAccessControlUserPresence.
	AccessControlUserPresence AccessControlFlags = 1 << 0
	// AccessControlBiometryAny requires any enrolled biometric. New biometric
	// enrolments remain valid for the item. Equivalent to
	// kSecAccessControlBiometryAny.
	AccessControlBiometryAny AccessControlFlags = 1 << 1
	// AccessControlBiometryCurrentSet binds the item to the biometric set
	// at creation time; adding or removing a fingerprint/face invalidates
	// the item. Equivalent to kSecAccessControlBiometryCurrentSet.
	AccessControlBiometryCurrentSet AccessControlFlags = 1 << 3
	// AccessControlDevicePasscode requires the device passcode. Equivalent
	// to kSecAccessControlDevicePasscode.
	AccessControlDevicePasscode AccessControlFlags = 1 << 4
	// AccessControlOr makes multiple constraints satisfiable with any one
	// factor (the default when multiple factors are listed).
	AccessControlOr AccessControlFlags = 1 << 14
	// AccessControlAnd requires every listed factor.
	AccessControlAnd AccessControlFlags = 1 << 15
	// AccessControlApplicationPassword requires an application-provided
	// password in addition to the listed factors. Rarely useful here.
	AccessControlApplicationPassword AccessControlFlags = 1 << 30
)

// AccessControlKey is the attribute key for kSecAttrAccessControl.
//
// Items created with kSecAttrAccessControl must NOT also carry
// kSecAttrAccessible — the protection class is baked into the access control
// object itself. Callers that opt into access control should leave Accessible
// unset on the Item.
var AccessControlKey = attrKey(C.CFTypeRef(C.kSecAttrAccessControl))

// UseOperationPromptKey is the attribute key for kSecUseOperationPrompt.
// It is set at query time (Get / QueryItem) to customise the message shown
// in the Touch ID / Face ID / passcode prompt.
var UseOperationPromptKey = attrKey(C.CFTypeRef(C.kSecUseOperationPrompt))

// AccessControl describes an access-control policy that gets materialised
// into a SecAccessControl object each time the keychain item is built. It
// implements [Convertable] so ConvertMapToCFDictionary releases the freshly
// created CFTypeRef once the enclosing dictionary is no longer needed.
//
// We build the ref lazily (in Convert) rather than at SetAccessControl
// time so the Item remains safe to reuse across AddItem/QueryItem calls
// without leaking — the alternative of caching one ref per Item is harder
// to reason about because the dictionary may be created multiple times
// during a single store operation (Save→Delete→Save retry, etc.).
type AccessControl struct {
	Protection Accessible
	Flags      AccessControlFlags
}

// Convert is called by ConvertMapToCFDictionary; the returned ref is owned
// by the caller and the framework defers Release on it.
func (a AccessControl) Convert() (C.CFTypeRef, error) {
	protectionRef, ok := accessibleTypeRef[a.Protection]
	if !ok {
		return 0, fmt.Errorf("unsupported protection class for access control: %d", a.Protection)
	}

	var cfErr C.CFErrorRef
	acl := C.SecAccessControlCreateWithFlags(
		C.kCFAllocatorDefault,
		protectionRef,
		C.SecAccessControlCreateFlags(a.Flags),
		&cfErr,
	)
	if acl == 0 {
		if cfErr != 0 {
			defer C.CFRelease(C.CFTypeRef(cfErr))
			return 0, fmt.Errorf("SecAccessControlCreateWithFlags: %s",
				CFStringToString(C.CFErrorCopyDescription(cfErr)))
		}
		return 0, errors.New("SecAccessControlCreateWithFlags returned nil")
	}
	return C.CFTypeRef(acl), nil
}

// SetAccessControl attaches a SecAccessControl policy to the item's
// kSecAttrAccessControl attribute, requiring the listed authentication
// factors before the keychain releases the secret. The protection class
// replaces the role normally played by Accessible — callers should not also
// call SetAccessible on the same item.
func (k *Item) SetAccessControl(protection Accessible, flags AccessControlFlags) {
	// Drop any previously-set Accessible attribute: the protection class is
	// encoded inside the SecAccessControl object, and supplying both
	// confuses SecItemAdd (errSecParam).
	delete(k.attr, AccessibleKey)
	k.attr[AccessControlKey] = AccessControl{Protection: protection, Flags: flags}
}

// SetUseOperationPrompt sets kSecUseOperationPrompt on a query so the
// Touch ID / Face ID / passcode dialog shows the supplied message. Empty
// strings clear the attribute. This is read-side only; it has no effect at
// item creation.
func (k *Item) SetUseOperationPrompt(prompt string) {
	k.SetString(UseOperationPromptKey, prompt)
}
