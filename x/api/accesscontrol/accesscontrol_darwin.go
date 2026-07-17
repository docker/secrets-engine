// Copyright 2026 Docker, Inc.
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

package accesscontrol

type SigningInfo struct {
	SigningInfoBase

	// TeamID is the Apple-assigned Team Identifier (kSecCodeInfoTeamIdentifier),
	// Apple guarantees this is unique per developer account.
	TeamID string

	// Identifier is the code signing identifier (kSecCodeInfoIdentifier),
	// typically the bundle ID, e.g. "com.docker.docker". Use to pin a specific
	// application within a team.
	Identifier string

	// Organization is the company name from the leaf certificate subject.O,
	// e.g. "Docker Inc". Human-readable but NOT guaranteed unique or immutable,
	// so suitable for display/logging rather than as a sole trust key.
	Organization string

	// CommonName is the leaf certificate subject.CN, e.g.
	// "Developer ID Application: Docker Inc (<team-id>)". Contains the company
	// name and TeamID as embedded display text.
	CommonName string

	// CDHash is the code directory hash (kSecCodeInfoUnique), the exact identity
	// of this specific binary build, hex-encoded. Use to pin an exact build.
	CDHash string

	// Status is the dynamic code signing status word (kSecCodeInfoStatus) — the
	// kernel's live view of the signature, as opposed to the static on-disk
	// signature. See CodeStatus for the individual flags. Validity is already
	// enforced by SecCodeCheckValidityWithErrors, so this is primarily
	// corroborating/diagnostic (notably the Debugged flag).
	Status CodeStatus
}

// CodeStatus is a bitmask of the dynamic SecCodeStatus flags reported in
// kSecCodeInfoStatus. The values are fixed by Apple's <Security/SecCode.h>;
// they are not ours to renumber.
type CodeStatus uint32

const (
	// StatusValid: signature is dynamically valid; cleared if the process was
	// tampered/invalidated at runtime (e.g. code injection).
	StatusValid CodeStatus = 0x0001
	// StatusHard: kernel refuses to page in invalid pages, so tampered code
	// will not silently run.
	StatusHard CodeStatus = 0x0100
	// StatusKill: process is killed if it ever becomes invalid.
	StatusKill CodeStatus = 0x0200
	// StatusDebugged: a debugger is/was attached — a red flag for a secrets
	// connection.
	StatusDebugged CodeStatus = 0x1000_0000
)
