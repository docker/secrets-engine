package accesscontrol

// SigningInfo holds the identity and security posture of a peer process on
// Windows. It draws on three distinct sources with very different trust
// properties:
//
//   - Signature-derived fields are verified by WinVerifyTrust (the Authenticode
//     chain-to-trusted-root check) and are trustworthy. Trust is gated on these
//     alone (SignedByDocker + IsEV).
//   - Token-derived fields come from the peer's OS security token —
//     trustworthy, OS-enforced runtime properties, but they do not gate trust.
//   - Corroborating fields come from the PE version resource, which is
//     unsigned and attacker-controllable — suitable for logging only, never as
//     a trust input.
//
// Windows verification is static: it inspects the on-disk PE image and cannot
// detect in-memory tampering (process hollowing / injection) of an otherwise
// validly signed binary. Trust rests entirely on the signature-derived fields.
type SigningInfo struct {
	SigningInfoBase

	// --- Signature-derived (verified by WinVerifyTrust) ---
	//
	// Known limitation (as of today): these fields describe the PE's primary
	// Authenticode signature only. A PE may carry additional nested signatures
	// (e.g. SHA-1 + SHA-256 for algorithm agility); those are not enumerated. This
	// is safe — trust is gated on the primary signature, so extra signatures
	// cannot grant trust — and sufficient for Docker, whose EV identity is on the
	// primary signature. The only cost is a theoretical false negative if a
	// legitimate peer carried its Docker identity solely in a nested signature.

	// TrustedChain reports whether WinVerifyTrust confirmed the Authenticode
	// signature chains to a trusted root and is not revoked.
	// The remaining signature fields are only meaningful when it is true.
	TrustedChain bool

	// SubjectOrg is the signing certificate Subject Organization (O), e.g. "Docker Inc".
	SubjectOrg string

	// SubjectCommonName is the signing certificate Subject Common Name (CN).
	SubjectCommonName string

	// Issuer is the Common Name of the issuing CA, e.g. the DigiCert / Sectigo
	// code-signing intermediate.
	Issuer string

	// ThumbprintSHA256 is the hex-encoded SHA-256 hash of the leaf signing
	// certificate. Strongest identity pin, but brittle across cert rotation.
	ThumbprintSHA256 string

	// IsEV reports whether the signature uses an Extended Validation
	// code-signing certificate (hardware-backed key, stricter vetting), detected
	// from the leaf certificate's CA/Browser Forum EV policy OID.
	IsEV bool

	// --- Token-derived (OS-enforced runtime properties; collected, not gated) ---

	// Integrity is the peer process's mandatory integrity level (Low/Medium/
	// High/System) from its access token — an OS-enforced runtime property.
	Integrity IntegrityLevel

	// --- Corroborating only (PE version resource; NOT trustworthy) ---

	// CompanyName, ProductName, and FileVersion come from the PE VERSIONINFO
	// resource. This metadata is unsigned and attacker-controllable, so it is
	// for display/logging only and must never gate trust.
	CompanyName string
	ProductName string
	FileVersion string
}

// IntegrityLevel is a Windows mandatory integrity level, ordered so that higher
// values denote a more privileged context. Mirrors winnt.h.
type IntegrityLevel uint32

const (
	// IntegrityUntrusted is SECURITY_MANDATORY_UNTRUSTED_RID (0x0000). Also the
	// zero value, used when the integrity level could not be determined.
	IntegrityUntrusted IntegrityLevel = 0x0000
	// IntegrityLow is SECURITY_MANDATORY_LOW_RID (0x1000), e.g. AppContainer or
	// sandboxed processes.
	IntegrityLow IntegrityLevel = 0x1000
	// IntegrityMedium is SECURITY_MANDATORY_MEDIUM_RID (0x2000), the default for
	// standard user processes.
	IntegrityMedium IntegrityLevel = 0x2000
	// IntegrityHigh is SECURITY_MANDATORY_HIGH_RID (0x3000), e.g. elevated
	// (administrator) processes.
	IntegrityHigh IntegrityLevel = 0x3000
	// IntegritySystem is SECURITY_MANDATORY_SYSTEM_RID (0x4000), e.g. services
	// running as SYSTEM.
	IntegritySystem IntegrityLevel = 0x4000
)
