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

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSigningInfoRoundTrip(t *testing.T) {
	t.Parallel()

	si := SigningInfo{
		SigningInfoBase:   SigningInfoBase{SignedByDocker: true},
		TrustedChain:      true,
		SubjectOrg:        "Docker Inc",
		SubjectCommonName: "Docker Inc",
		Issuer:            "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1",
		ThumbprintSHA256:  "deadbeef",
		IsEV:              true,
		Integrity:         IntegrityMedium,
		CompanyName:       "Docker Inc",
		ProductName:       "Docker Desktop",
		FileVersion:       "4.43.0",
	}

	assert.Equal(t, si, signingInfoFromProto(NewRequester(ProcessInfo{}, si)))
}

func TestIntegrityLevelRoundTrip(t *testing.T) {
	t.Parallel()

	for _, lvl := range []IntegrityLevel{IntegrityUntrusted, IntegrityLow, IntegrityMedium, IntegrityHigh, IntegritySystem} {
		si := SigningInfo{Integrity: lvl}
		assert.Equal(t, si, signingInfoFromProto(NewRequester(ProcessInfo{}, si)), "integrity level %#x", uint32(lvl))
	}
}
