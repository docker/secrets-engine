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
	"google.golang.org/protobuf/types/known/timestamppb"

	accesscontrolv1 "github.com/docker/secrets-engine/x/api/accesscontrol/v1"
)

// setPlatformSigningInfo is the inverse of signingInfoFromProto for Darwin.
func setPlatformSigningInfo(b *accesscontrolv1.Requester_builder, si SigningInfo) {
	db := accesscontrolv1.DarwinSigningInfo_builder{
		Root: signingIdentityToProto(si.Root),
		Leaf: signingIdentityToProto(si.Leaf),
	}
	for _, n := range si.Chain {
		nb := accesscontrolv1.DarwinSigningInfo_ProcessNode_builder{
			Pid:     proto.Int32(int32(n.PID)),
			Start:   proto.Int64(n.Start),
			Uid:     proto.Int32(int32(n.UID)),
			Comm:    proto.String(n.Comm),
			Exe:     proto.String(n.Exe),
			RealExe: proto.String(n.RealExe),
			Args:    n.Args,
		}
		// Zero Mtime round-trips to the zero time.Time, not the Unix epoch.
		if !n.Mtime.IsZero() {
			nb.Mtime = timestamppb.New(n.Mtime)
		}
		db.Chain = append(db.Chain, nb.Build())
	}
	b.Darwin = db.Build()
}

func signingIdentityToProto(id *SigningIdentity) *accesscontrolv1.DarwinSigningInfo_SigningIdentity {
	if id == nil {
		return nil
	}
	return accesscontrolv1.DarwinSigningInfo_SigningIdentity_builder{
		SignedByDocker: proto.Bool(id.SignedByDocker),
		TeamId:         proto.String(id.TeamID),
		Identifier:     proto.String(id.Identifier),
		Organization:   proto.String(id.Organization),
		BundleName:     proto.String(id.BundleName),
		CommonName:     proto.String(id.CommonName),
		CdHash:         proto.String(id.CDHash),
		Status:         proto.Uint32(uint32(id.Status)),
		Anchor:         anchorToProto(id.Anchor),
	}.Build()
}

func anchorToProto(a Anchor) *accesscontrolv1.DarwinSigningInfo_Anchor {
	v := accesscontrolv1.DarwinSigningInfo_ANCHOR_NONE
	switch a {
	case AnchorAdHoc:
		v = accesscontrolv1.DarwinSigningInfo_ANCHOR_AD_HOC
	case AnchorOther:
		v = accesscontrolv1.DarwinSigningInfo_ANCHOR_OTHER
	case AnchorAppleGeneric:
		v = accesscontrolv1.DarwinSigningInfo_ANCHOR_APPLE_GENERIC
	case AnchorApplePlatform:
		v = accesscontrolv1.DarwinSigningInfo_ANCHOR_APPLE_PLATFORM
	}
	return &v
}
