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
	"math"

	"google.golang.org/protobuf/proto"

	accesscontrolv1 "github.com/docker/secrets-engine/x/api/accesscontrol/v1"
)

// NewRequester encodes the caller's identity into its canonical wire form,
// the inverse of the connect handler's decoding.
func NewRequester(info ProcessInfo, si SigningInfo) *accesscontrolv1.Requester {
	b := accesscontrolv1.Requester_builder{
		Name:               proto.String(info.Name),
		AbsoluteBinaryPath: proto.String(info.AbsoluteBinaryPath),
	}
	if info.PID >= 0 && info.PID <= math.MaxInt32 {
		b.Pid = proto.Int32(int32(info.PID))
	}
	setPlatformSigningInfo(&b, si)
	return b.Build()
}
