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
	"google.golang.org/protobuf/proto"

	accesscontrolv1 "github.com/docker/secrets-engine/x/api/accesscontrol/v1"
)

// setPlatformSigningInfo is the inverse of signingInfoFromProto for Windows.
func setPlatformSigningInfo(b *accesscontrolv1.Requester_builder, si SigningInfo) {
	b.SignedByDocker = proto.Bool(si.SignedByDocker)
	b.Windows = accesscontrolv1.WindowsSigningInfo_builder{
		TrustedChain:      proto.Bool(si.TrustedChain),
		SubjectOrg:        proto.String(si.SubjectOrg),
		SubjectCommonName: proto.String(si.SubjectCommonName),
		Issuer:            proto.String(si.Issuer),
		ThumbprintSha256:  proto.String(si.ThumbprintSHA256),
		IsEv:              proto.Bool(si.IsEV),
		Integrity:         integrityLevelToProto(si.Integrity),
		CompanyName:       proto.String(si.CompanyName),
		ProductName:       proto.String(si.ProductName),
		FileVersion:       proto.String(si.FileVersion),
	}.Build()
}

func integrityLevelToProto(v IntegrityLevel) *accesscontrolv1.WindowsSigningInfo_IntegrityLevel {
	lvl := accesscontrolv1.WindowsSigningInfo_INTEGRITY_LEVEL_UNSPECIFIED
	switch v {
	case IntegrityLow:
		lvl = accesscontrolv1.WindowsSigningInfo_INTEGRITY_LEVEL_LOW
	case IntegrityMedium:
		lvl = accesscontrolv1.WindowsSigningInfo_INTEGRITY_LEVEL_MEDIUM
	case IntegrityHigh:
		lvl = accesscontrolv1.WindowsSigningInfo_INTEGRITY_LEVEL_HIGH
	case IntegritySystem:
		lvl = accesscontrolv1.WindowsSigningInfo_INTEGRITY_LEVEL_SYSTEM
	}
	return &lvl
}
