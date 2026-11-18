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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewRequester_ProcessInfo(t *testing.T) {
	t.Parallel()

	pb := NewRequester(ProcessInfo{PID: 42, Name: "app", AbsoluteBinaryPath: "/bin/app"}, SigningInfo{})
	assert.Equal(t, int32(42), pb.GetPid())
	assert.Equal(t, "app", pb.GetName())
	assert.Equal(t, "/bin/app", pb.GetAbsoluteBinaryPath())

	pb = NewRequester(ProcessInfo{PID: math.MaxInt32}, SigningInfo{})
	assert.Equal(t, int32(math.MaxInt32), pb.GetPid())

	pb = NewRequester(ProcessInfo{PID: -1}, SigningInfo{})
	assert.False(t, pb.HasPid())
}

func TestSigningInfoRoundTrip_Zero(t *testing.T) {
	t.Parallel()

	assert.Equal(t, SigningInfo{}, signingInfoFromProto(NewRequester(ProcessInfo{}, SigningInfo{})))
}
