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

import (
	"context"
	"fmt"

	"connectrpc.com/connect"

	accesscontrolv1 "github.com/docker/secrets-engine/x/api/accesscontrol/v1"
	"github.com/docker/secrets-engine/x/api/accesscontrol/v1/accesscontrolv1connect"
	"github.com/docker/secrets-engine/x/secrets"
)

var _ accesscontrolv1connect.AccessControlServiceHandler = &accessControlService{}

type accessControlService struct {
	ac AccessControl
}

// NewAccessControlHandler adapts an AccessControl implementation to the
// generated connect handler interface.
func NewAccessControlHandler(ac AccessControl) accesscontrolv1connect.AccessControlServiceHandler {
	return &accessControlService{ac}
}

func (s *accessControlService) CheckAccess(ctx context.Context, c *connect.Request[accesscontrolv1.CheckAccessRequest]) (*connect.Response[accesscontrolv1.CheckAccessResponse], error) {
	msgPattern := c.Msg.GetPattern()
	pattern, err := secrets.ParsePattern(msgPattern)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid pattern %q: %w", msgPattern, err))
	}

	requester := c.Msg.GetRequester()
	if requester == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("requester is required"))
	}
	req := CheckAccessRequest{
		Pattern: pattern,
		ProcessInfo: ProcessInfo{
			PID:                int(requester.GetPid()),
			Name:               requester.GetName(),
			AbsoluteBinaryPath: requester.GetAbsoluteBinaryPath(),
		},
		SigningInfo: signingInfoFromProto(requester),
	}

	allowed, err := s.ac.CheckAccess(ctx, req)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("access check failed for %q: %w", msgPattern, err))
	}

	decision := accesscontrolv1.Decision_DECISION_DENY
	if allowed {
		decision = accesscontrolv1.Decision_DECISION_ALLOW
	}
	return connect.NewResponse(accesscontrolv1.CheckAccessResponse_builder{
		Decision: &decision,
	}.Build()), nil
}
