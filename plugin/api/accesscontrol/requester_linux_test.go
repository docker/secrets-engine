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
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSigningInfoRoundTrip(t *testing.T) {
	t.Parallel()

	si := SigningInfo{
		SigningInfoBase: SigningInfoBase{SignedByDocker: true},
		Signers: []Signer{
			{
				CertIssuer:        "https://token.actions.githubusercontent.com",
				CertIdentity:      "https://github.com/docker/secrets-engine/.github/workflows/sign-release.yml@refs/tags/v0.7.1",
				SourceRepo:        "https://github.com/docker/secrets-engine",
				SourceRef:         "refs/tags/v0.7.1",
				SourceCommit:      "295f927e",
				RunnerEnvironment: "github-hosted",
				BuildTrigger:      "release",
				RunInvocationURI:  "https://github.com/docker/secrets-engine/actions/runs/1",
				RekorLogIndex:     123456,
				IntegratedTime:    time.Date(2026, 8, 20, 10, 0, 0, 123456789, time.UTC),
			},
			// Zero IntegratedTime pins the unset-timestamp round trip.
			{CertIssuer: "https://accounts.google.com", RekorLogIndex: 7},
		},
	}

	assert.Equal(t, si, signingInfoFromProto(NewRequester(ProcessInfo{}, si)))
}
