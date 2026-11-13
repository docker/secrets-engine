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
	"errors"
	"fmt"

	"google.golang.org/protobuf/types/known/timestamppb"

	accesscontrolv1 "github.com/docker/secrets-engine/plugin/api/accesscontrol/v1"
	"github.com/docker/secrets-engine/plugin/api/accesscontrol/v1/accesscontrolv1rpc"
	"github.com/docker/secrets-engine/plugin/rpc"
	"github.com/docker/secrets-engine/secrets"
)

var _ accesscontrolv1rpc.AccessControlServiceHandler = &accessControlService{}

type accessControlService struct {
	ac AccessControl
}

// NewAccessControlHandler adapts an ACM implementation to the
// AccessControlService handler interface.
func NewAccessControlHandler(acm AccessControl) accesscontrolv1rpc.AccessControlServiceHandler {
	return &accessControlService{ac: acm}
}

func (s *accessControlService) CheckAccess(ctx context.Context, msg *accesscontrolv1.CheckAccessRequest) (*accesscontrolv1.CheckAccessResponse, error) {
	msgPattern := msg.GetPattern()
	pattern, err := secrets.ParsePattern(msgPattern)
	if err != nil {
		return nil, rpc.NewError(rpc.CodeInvalidArgument, fmt.Errorf("invalid pattern %q: %w", msgPattern, err))
	}

	requester := msg.GetRequester()
	if requester == nil {
		return nil, rpc.NewError(rpc.CodeInvalidArgument, fmt.Errorf("requester is required"))
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
		return nil, rpc.NewError(rpc.CodeInternal, fmt.Errorf("access check failed for %q: %w", msgPattern, err))
	}

	decision := accesscontrolv1.Decision_DECISION_DENY
	if allowed {
		decision = accesscontrolv1.Decision_DECISION_ALLOW
	}
	return accesscontrolv1.CheckAccessResponse_builder{
		Decision: &decision,
	}.Build(), nil
}

func (s *accessControlService) Authorize(ctx context.Context, msg *accesscontrolv1.AuthorizeRequest) (*accesscontrolv1.AuthorizeResponse, error) {
	msgPatterns := msg.GetPatterns()
	patterns, err := parsePatterns(msgPatterns)
	if err != nil {
		return nil, err
	}

	requester := msg.GetRequester()
	if requester == nil {
		return nil, rpc.NewError(rpc.CodeInvalidArgument, fmt.Errorf("requester is required"))
	}
	req := AuthorizeRequest{
		Patterns: patterns,
		ProcessInfo: ProcessInfo{
			PID:                int(requester.GetPid()),
			Name:               requester.GetName(),
			AbsoluteBinaryPath: requester.GetAbsoluteBinaryPath(),
		},
		SigningInfo: signingInfoFromProto(requester),
	}

	resp, err := s.ac.Authorize(ctx, req)
	if err != nil {
		if errors.Is(err, secrets.ErrAccessDenied) {
			return nil, rpc.NewError(rpc.CodePermissionDenied, secrets.ErrAccessDenied)
		}
		return nil, rpc.NewError(rpc.CodeInternal, fmt.Errorf("authorize failed for %q: %w", msgPatterns, err))
	}
	decision := accesscontrolv1.Decision_DECISION_DENY
	if resp.Allow {
		decision = accesscontrolv1.Decision_DECISION_ALLOW
	}
	return accesscontrolv1.AuthorizeResponse_builder{
		ExpiresAt: timestamppb.New(resp.Expiry),
		Decision:  &decision,
	}.Build(), nil
}

func parsePatterns(msgPatterns []string) ([]secrets.Pattern, error) {
	if len(msgPatterns) == 0 {
		return nil, rpc.NewError(rpc.CodeInvalidArgument, fmt.Errorf("at least one pattern is required"))
	}
	patterns := make([]secrets.Pattern, 0, len(msgPatterns))
	for _, msgPattern := range msgPatterns {
		pattern, err := secrets.ParsePattern(msgPattern)
		if err != nil {
			return nil, rpc.NewError(rpc.CodeInvalidArgument, fmt.Errorf("invalid pattern %q: %w", msgPattern, err))
		}
		patterns = append(patterns, pattern)
	}
	return patterns, nil
}
