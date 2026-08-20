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

// setPlatformSigningInfo is the inverse of signingInfoFromProto for Linux.
func setPlatformSigningInfo(b *accesscontrolv1.Requester_builder, si SigningInfo) {
	b.SignedByDocker = proto.Bool(si.SignedByDocker)
	signers := make([]*accesscontrolv1.LinuxSigningInfo_Signer, 0, len(si.Signers))
	for _, s := range si.Signers {
		sb := accesscontrolv1.LinuxSigningInfo_Signer_builder{
			CertIssuer:        proto.String(s.CertIssuer),
			CertIdentity:      proto.String(s.CertIdentity),
			SourceRepo:        proto.String(s.SourceRepo),
			SourceRef:         proto.String(s.SourceRef),
			SourceCommit:      proto.String(s.SourceCommit),
			RunnerEnvironment: proto.String(s.RunnerEnvironment),
			BuildTrigger:      proto.String(s.BuildTrigger),
			RunInvocationUri:  proto.String(s.RunInvocationURI),
			RekorLogIndex:     proto.Int64(s.RekorLogIndex),
		}
		// Zero IntegratedTime round-trips to the zero time.Time, not the Unix epoch.
		if !s.IntegratedTime.IsZero() {
			sb.IntegratedTime = timestamppb.New(s.IntegratedTime)
		}
		signers = append(signers, sb.Build())
	}
	b.Linux = accesscontrolv1.LinuxSigningInfo_builder{Signers: signers}.Build()
}
