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
	l := r.GetLinux()
	if l == nil {
		return si
	}
	for _, s := range l.GetSigners() {
		signer := Signer{
			CertIssuer:        s.GetCertIssuer(),
			CertIdentity:      s.GetCertIdentity(),
			SourceRepo:        s.GetSourceRepo(),
			SourceRef:         s.GetSourceRef(),
			SourceCommit:      s.GetSourceCommit(),
			RunnerEnvironment: s.GetRunnerEnvironment(),
			BuildTrigger:      s.GetBuildTrigger(),
			RunInvocationURI:  s.GetRunInvocationUri(),
			RekorLogIndex:     s.GetRekorLogIndex(),
		}
		// Leave IntegratedTime as the zero time.Time when unset; AsTime() on a
		// nil Timestamp would otherwise yield the Unix epoch (1970), which
		// IsZero() reports as non-zero and staleness checks misread.
		if t := s.GetIntegratedTime(); t != nil {
			signer.IntegratedTime = t.AsTime()
		}
		si.Signers = append(si.Signers, signer)
	}
	return si
}
