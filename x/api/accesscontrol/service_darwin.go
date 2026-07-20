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
	si := SigningInfo{
		SigningInfoBase: SigningInfoBase{SignedByDocker: r.GetSignedByDocker()},
	}
	d := r.GetDarwin()
	if d == nil {
		return si
	}
	si.TeamID = d.GetTeamId()
	si.Identifier = d.GetIdentifier()
	si.Organization = d.GetOrganization()
	si.CommonName = d.GetCommonName()
	si.CDHash = d.GetCdHash()
	si.Status = CodeStatus(d.GetStatus())
	return si
}
