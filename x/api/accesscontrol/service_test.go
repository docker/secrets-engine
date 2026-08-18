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
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	accesscontrolv1 "github.com/docker/secrets-engine/x/api/accesscontrol/v1"
)

type stubAccessControl struct {
	called  bool
	req     CheckAccessRequest
	allowed bool
	err     error
}

func (s *stubAccessControl) CheckAccess(_ context.Context, req CheckAccessRequest) (bool, error) {
	s.called = true
	s.req = req
	return s.allowed, s.err
}

func TestCheckAccess(t *testing.T) {
	t.Parallel()

	t.Run("requires at least one pattern", func(t *testing.T) {
		ac := &stubAccessControl{allowed: true}
		svc := NewAccessControlHandler(ac)

		req := connect.NewRequest(accesscontrolv1.CheckAccessRequest_builder{
			Requester: accesscontrolv1.Requester_builder{Pid: proto.Int32(42)}.Build(),
		}.Build())

		_, err := svc.CheckAccess(t.Context(), req)
		require.Error(t, err)
		assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
		assert.ErrorContains(t, err, "at least one pattern is required")
		assert.False(t, ac.called, "access control must not run without a pattern")
	})

	t.Run("forwards all patterns", func(t *testing.T) {
		ac := &stubAccessControl{allowed: true}
		svc := NewAccessControlHandler(ac)

		req := connect.NewRequest(accesscontrolv1.CheckAccessRequest_builder{
			Patterns:  []string{"docker/auth/hub/joe", "acme/api-token"},
			Requester: accesscontrolv1.Requester_builder{Pid: proto.Int32(42)}.Build(),
		}.Build())

		resp, err := svc.CheckAccess(t.Context(), req)
		require.NoError(t, err)
		assert.Equal(t, accesscontrolv1.Decision_DECISION_ALLOW, resp.Msg.GetDecision())

		require.True(t, ac.called)
		require.Len(t, ac.req.Patterns, 2)
		assert.Equal(t, "docker/auth/hub/joe", ac.req.Patterns[0].String())
		assert.Equal(t, "acme/api-token", ac.req.Patterns[1].String())
	})
}
