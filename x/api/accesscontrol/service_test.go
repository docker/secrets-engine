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
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	accesscontrolv1 "github.com/docker/secrets-engine/x/api/accesscontrol/v1"
	"github.com/docker/secrets-engine/x/secrets"
)

type stubAccessControl struct {
	called  bool
	req     CheckAccessRequest
	allowed bool
	err     error

	authReq AuthorizeRequest
	expiry  time.Time
}

func (s *stubAccessControl) CheckAccess(_ context.Context, req CheckAccessRequest) (bool, error) {
	s.called = true
	s.req = req
	return s.allowed, s.err
}

func (s *stubAccessControl) Authorize(_ context.Context, req AuthorizeRequest) (time.Time, error) {
	s.called = true
	s.authReq = req
	return s.expiry, s.err
}

func TestCheckAccess(t *testing.T) {
	t.Parallel()

	t.Run("rejects a missing pattern", func(t *testing.T) {
		ac := &stubAccessControl{allowed: true}
		svc := NewAccessControlHandler(ac)

		req := connect.NewRequest(accesscontrolv1.CheckAccessRequest_builder{
			Requester: accesscontrolv1.Requester_builder{Pid: proto.Int32(42)}.Build(),
		}.Build())

		_, err := svc.CheckAccess(t.Context(), req)
		require.Error(t, err)
		assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
		assert.ErrorContains(t, err, "invalid pattern")
		assert.False(t, ac.called, "access control must not run without a pattern")
	})

	t.Run("forwards the pattern", func(t *testing.T) {
		ac := &stubAccessControl{allowed: true}
		svc := NewAccessControlHandler(ac)

		req := connect.NewRequest(accesscontrolv1.CheckAccessRequest_builder{
			Pattern:   proto.String("docker/auth/hub/joe"),
			Requester: accesscontrolv1.Requester_builder{Pid: proto.Int32(42)}.Build(),
		}.Build())

		resp, err := svc.CheckAccess(t.Context(), req)
		require.NoError(t, err)
		assert.Equal(t, accesscontrolv1.Decision_DECISION_ALLOW, resp.Msg.GetDecision())

		require.True(t, ac.called)
		assert.Equal(t, "docker/auth/hub/joe", ac.req.String())
	})
}

func TestAuthorize(t *testing.T) {
	t.Parallel()

	t.Run("requires at least one pattern", func(t *testing.T) {
		ac := &stubAccessControl{}
		svc := NewAccessControlHandler(ac)

		req := connect.NewRequest(accesscontrolv1.AuthorizeRequest_builder{
			Requester: accesscontrolv1.Requester_builder{Pid: proto.Int32(42)}.Build(),
		}.Build())

		_, err := svc.Authorize(t.Context(), req)
		require.Error(t, err)
		assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
		assert.ErrorContains(t, err, "at least one pattern is required")
		assert.False(t, ac.called, "access control must not run without a pattern")
	})

	t.Run("forwards all patterns", func(t *testing.T) {
		expiry := time.Now().Add(time.Hour).UTC()
		ac := &stubAccessControl{expiry: expiry}
		svc := NewAccessControlHandler(ac)

		req := connect.NewRequest(accesscontrolv1.AuthorizeRequest_builder{
			Patterns:  []string{"docker/auth/hub/joe", "acme/api-token"},
			Requester: accesscontrolv1.Requester_builder{Pid: proto.Int32(42)}.Build(),
		}.Build())

		resp, err := svc.Authorize(t.Context(), req)
		require.NoError(t, err)
		assert.True(t, resp.Msg.GetExpiresAt().AsTime().Equal(expiry), "expiry must round-trip")

		require.True(t, ac.called)
		require.Len(t, ac.authReq.Patterns, 2)
		assert.Equal(t, "docker/auth/hub/joe", ac.authReq.Patterns[0].String())
		assert.Equal(t, "acme/api-token", ac.authReq.Patterns[1].String())
	})

	t.Run("maps denial to permission denied", func(t *testing.T) {
		ac := &stubAccessControl{err: secrets.ErrAccessDenied}
		svc := NewAccessControlHandler(ac)

		req := connect.NewRequest(accesscontrolv1.AuthorizeRequest_builder{
			Patterns:  []string{"docker/auth/hub/joe"},
			Requester: accesscontrolv1.Requester_builder{Pid: proto.Int32(42)}.Build(),
		}.Build())

		_, err := svc.Authorize(t.Context(), req)
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	})
}
