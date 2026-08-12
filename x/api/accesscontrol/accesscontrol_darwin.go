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

import "time"

// Anchor classifies the root a process's code-signing certificate chain
// reaches. Values are ordered by increasing trust, so callers may gate on a
// minimum (e.g. Anchor >= AnchorAppleGeneric).
type Anchor uint8

const (
	AnchorNone          Anchor = iota // unsigned
	AnchorAdHoc                       // ad-hoc: a cdhash but no certificate (Homebrew formula, dev build)
	AnchorOther                       // signed with a chain that does not reach an Apple root
	AnchorAppleGeneric                // Developer ID or Mac App Store
	AnchorApplePlatform               // Apple's own platform binaries
)

func (a Anchor) String() string {
	switch a {
	case AnchorAdHoc:
		return "adhoc"
	case AnchorOther:
		return "other"
	case AnchorAppleGeneric:
		return "apple-generic"
	case AnchorApplePlatform:
		return "apple-platform"
	default:
		return "none"
	}
}

// SigningIdentity is the verified code-signing identity of a single process.
type SigningIdentity struct {
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

	// BundleName is the human-readable application name from the Info.plist
	// bound into the code signature (kSecCodeInfoPList, CFBundleDisplayName
	// falling back to CFBundleName), e.g. "Docker Desktop". Present for .app
	// bundles and bare binaries with an embedded __info_plist section; empty
	// otherwise. Display-only: chosen freely by the signer, not unique.
	BundleName string

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

	// Anchor classifies the root the certificate chain reaches.
	Anchor Anchor
}

// SigningInfo describes the code-signing identity of the requesting process
// and its process ancestry.
type SigningInfo struct {
	// Root is the code-signing identity of the outermost recorded ancestor.
	Root *SigningIdentity
	// Leaf is the code-signing identity of the process that connected to
	// the socket (last chain element).
	Leaf *SigningIdentity
	// Chain is the leaf's process ancestry ordered root to leaf. For a single-node
	// chain Root and Leaf describe the same process.
	Chain []ProcessNode
}

// ProcessNode is one process in the ancestry chain.
type ProcessNode struct {
	PID int
	// Start is the process start token in µs since epoch
	// (p_starttime sec*1e6 + µs). Together with PID it forms an instance
	// identity that survives PID reuse.
	Start int64
	// UID is the target process's effective uid.
	UID int

	// Comm is the kernel's process name (p_comm, 16 characters max, no root permissions required).
	Comm string

	// Exe is the executable path exactly as the kernel reports it (proc_pidpath).
	Exe string
	// RealExe is Exe with symlinks resolved, falling back to Exe.
	RealExe string
	// Mtime is the modification time of RealExe, UTC.
	Mtime time.Time

	// Args is the process argv via sysctl(KERN_PROCARGS2). Same-uid only
	// and best-effort: nil when unreadable. Self-reported by the process.
	Args []string
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
