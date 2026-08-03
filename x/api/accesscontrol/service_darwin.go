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

package accesscontrol

import accesscontrolv1 "github.com/docker/secrets-engine/x/api/accesscontrol/v1"

func signingInfoFromProto(r *accesscontrolv1.Requester) SigningInfo {
	d := r.GetDarwin()
	if d == nil {
		return SigningInfo{}
	}
	si := SigningInfo{
		Root: signingIdentityFromProto(d.GetRoot()),
		Leaf: signingIdentityFromProto(d.GetLeaf()),
	}
	for _, n := range d.GetChain() {
		node := ProcessNode{
			PID:     int(n.GetPid()),
			Start:   n.GetStart(),
			UID:     int(n.GetUid()),
			Comm:    n.GetComm(),
			Exe:     n.GetExe(),
			RealExe: n.GetRealExe(),
			Args:    n.GetArgs(),
		}
		// Leave Mtime as the zero time.Time when unset; AsTime() on a nil
		// Timestamp would otherwise yield the Unix epoch (1970), which
		// IsZero() reports as non-zero.
		if t := n.GetMtime(); t != nil {
			node.Mtime = t.AsTime()
		}
		si.Chain = append(si.Chain, node)
	}
	return si
}

func signingIdentityFromProto(p *accesscontrolv1.DarwinSigningInfo_SigningIdentity) *SigningIdentity {
	if p == nil {
		return nil
	}
	return &SigningIdentity{
		SigningInfoBase: SigningInfoBase{SignedByDocker: p.GetSignedByDocker()},
		TeamID:          p.GetTeamId(),
		Identifier:      p.GetIdentifier(),
		Organization:    p.GetOrganization(),
		CommonName:      p.GetCommonName(),
		CDHash:          p.GetCdHash(),
		Status:          CodeStatus(p.GetStatus()),
		Anchor:          anchorFromProto(p.GetAnchor()),
	}
}

func anchorFromProto(a accesscontrolv1.DarwinSigningInfo_Anchor) Anchor {
	switch a {
	case accesscontrolv1.DarwinSigningInfo_ANCHOR_AD_HOC:
		return AnchorAdHoc
	case accesscontrolv1.DarwinSigningInfo_ANCHOR_OTHER:
		return AnchorOther
	case accesscontrolv1.DarwinSigningInfo_ANCHOR_APPLE_GENERIC:
		return AnchorAppleGeneric
	case accesscontrolv1.DarwinSigningInfo_ANCHOR_APPLE_PLATFORM:
		return AnchorApplePlatform
	default:
		return AnchorNone
	}
}
