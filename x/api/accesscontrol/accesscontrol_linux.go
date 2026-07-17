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

type Signer struct {
	// --- Verified identity ---

	// CertIssuer is the OIDC issuer embedded in the Fulcio leaf certificate,
	// e.g. "https://token.actions.githubusercontent.com".
	CertIssuer string

	// CertIdentity is the certificate SAN — the signer's workflow identity, e.g.
	// "https://github.com/docker/secrets-engine/.github/workflows/sign-release.yml@refs/tags/v0.7.1".
	CertIdentity string

	// SourceRepo is the source repository URI from the Fulcio GitHub extension,
	// e.g. "https://github.com/docker/secrets-engine".
	SourceRepo string

	// --- Verified provenance (bound in the cert; diagnostic, not gated) ---

	// SourceRef is the git ref that was built, from the Fulcio extension, e.g.
	// "refs/tags/v0.7.1". Ties the binary to a release tag.
	SourceRef string

	// SourceCommit is the source commit SHA the binary was built from (the
	// Fulcio source-repository digest extension).
	SourceCommit string

	// RunnerEnvironment is "github-hosted" or "self-hosted" (Fulcio extension) —
	// a self-hosted runner minting a release signature would be a red flag.
	RunnerEnvironment string

	// BuildTrigger is the event that started the signing workflow, e.g.
	// "release" (Fulcio extension). Expected to be "release" for our workflow.
	BuildTrigger string

	// RunInvocationURI points at the specific GitHub Actions run that produced
	// the signature (Fulcio extension) — for audit/log correlation.
	RunInvocationURI string

	// --- Transparency log (verified inclusion) ---

	// RekorLogIndex is the entry's index in the Rekor transparency log.
	RekorLogIndex int64

	// IntegratedTime is when the signature was recorded in Rekor.
	IntegratedTime time.Time
}

type SigningInfo struct {
	SigningInfoBase

	Signers []Signer
}
