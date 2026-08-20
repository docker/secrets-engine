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
		Root: &SigningIdentity{
			SigningInfoBase: SigningInfoBase{SignedByDocker: true},
			TeamID:          "9BNSXJN65R",
			Identifier:      "com.docker.docker",
			Organization:    "Docker Inc",
			BundleName:      "Docker Desktop",
			CommonName:      "Developer ID Application: Docker Inc (9BNSXJN65R)",
			CDHash:          "aabbcc",
			Status:          StatusValid | StatusHard,
			Anchor:          AnchorAppleGeneric,
		},
		Leaf: &SigningIdentity{
			TeamID:     "24VZTF6M5V",
			Identifier: "com.mitchellh.ghostty",
			Status:     StatusValid | StatusDebugged,
			Anchor:     AnchorAdHoc,
		},
		Chain: []ProcessNode{
			{
				PID:     1,
				Start:   1700000000000001,
				UID:     0,
				Comm:    "launchd",
				Exe:     "/sbin/launchd",
				RealExe: "/sbin/launchd",
				Mtime:   time.Date(2026, 8, 20, 10, 0, 0, 123456789, time.UTC),
				Args:    []string{"/sbin/launchd"},
			},
			{PID: 42, Start: 1700000000000002, UID: 501, Comm: "ghostty", Exe: "/tmp/ghostty"},
		},
	}

	assert.Equal(t, si, signingInfoFromProto(NewRequester(ProcessInfo{}, si)))
}

func TestAnchorRoundTrip(t *testing.T) {
	t.Parallel()

	for _, a := range []Anchor{AnchorNone, AnchorAdHoc, AnchorOther, AnchorAppleGeneric, AnchorApplePlatform} {
		si := SigningInfo{Leaf: &SigningIdentity{Anchor: a}}
		assert.Equal(t, si, signingInfoFromProto(NewRequester(ProcessInfo{}, si)), "anchor %s", a)
	}
}
