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

package resolver

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	clientresolver "github.com/docker/secrets-engine/client/api/resolver"
	resolverv1 "github.com/docker/secrets-engine/client/api/resolver/v1"
	"github.com/docker/secrets-engine/plugin/api/resolver/v1/resolverv1rpc"
	"github.com/docker/secrets-engine/plugin/rpc"
	"github.com/docker/secrets-engine/secrets"
)

var _ resolverv1rpc.ResolverServiceHandler = &resolverService{}

type resolverService struct {
	resolver clientresolver.Resolver
}

func NewResolverHandler(r clientresolver.Resolver) resolverv1rpc.ResolverServiceHandler {
	return &resolverService{r}
}

func (r resolverService) GetSecrets(ctx context.Context, req *resolverv1.GetSecretsRequest) (*resolverv1.GetSecretsResponse, error) {
	msgPattern := req.GetPattern()
	pattern, err := secrets.ParsePattern(msgPattern)
	if err != nil {
		return nil, rpc.NewError(rpc.CodeInvalidArgument, fmt.Errorf("invalid pattern %q: %w", msgPattern, err))
	}

	envelopes, err := r.resolver.GetSecrets(ctx, pattern)
	if err != nil {
		if errors.Is(err, secrets.ErrNotFound) {
			return nil, rpc.NewError(rpc.CodeNotFound, secrets.ErrNotFound)
		}
		return nil, rpc.NewError(rpc.CodeInternal, fmt.Errorf("failed to get secret %q: %w", msgPattern, err))
	}
	if len(envelopes) == 0 {
		return nil, rpc.NewError(rpc.CodeNotFound, secrets.ErrNotFound)
	}
	var items []*resolverv1.GetSecretsResponse_Envelope
	for _, envelope := range envelopes {
		items = append(items, resolverv1.GetSecretsResponse_Envelope_builder{
			Id:         proto.String(envelope.ID.String()),
			Value:      envelope.Value,
			Metadata:   envelope.Metadata,
			Provider:   proto.String(envelope.Provider),
			Version:    proto.String(envelope.Version),
			CreatedAt:  timestamppb.New(envelope.CreatedAt),
			ResolvedAt: timestamppb.New(envelope.ResolvedAt),
			ExpiresAt:  timestamppb.New(envelope.ExpiresAt),
		}.Build())
	}
	return resolverv1.GetSecretsResponse_builder{
		Envelopes: items,
	}.Build(), nil
}

var _ clientresolver.Resolver = &resolverClient{}

type resolverClient struct {
	resolverClient resolverv1rpc.ResolverServiceClient
}

func NewResolverClient(httpClient rpc.HTTPClient) clientresolver.Resolver {
	return &resolverClient{resolverClient: resolverv1rpc.NewResolverServiceClient(httpClient, "http://unix")}
}

func (r resolverClient) GetSecrets(ctx context.Context, pattern secrets.Pattern) ([]secrets.Envelope, error) {
	resp, err := r.resolverClient.GetSecrets(ctx, resolverv1.GetSecretsRequest_builder{
		Pattern: proto.String(pattern.String()),
	}.Build())
	if err != nil {
		if rpc.CodeOf(err) == rpc.CodeNotFound {
			err = secrets.ErrNotFound
		}
		return nil, err
	}

	var envelopes []secrets.Envelope
	for _, item := range resp.GetEnvelopes() {
		id, err := secrets.ParseID(item.GetId())
		if err != nil {
			continue
		}
		envelopes = append(envelopes, secrets.Envelope{
			ID:         id,
			Value:      item.GetValue(),
			Metadata:   item.GetMetadata(),
			Provider:   item.GetProvider(),
			Version:    item.GetVersion(),
			CreatedAt:  item.GetCreatedAt().AsTime(),
			ResolvedAt: item.GetResolvedAt().AsTime(),
			ExpiresAt:  item.GetExpiresAt().AsTime(),
		})
	}
	return envelopes, nil
}

var _ resolverv1rpc.AuthorizerServiceHandler = &authorizerService{}

type authorizerService struct {
	authorizer clientresolver.Authorizer
}

// NewAuthorizerHandler adapts a resolver.Authorizer to the AuthorizerService
// handler interface. It is served by the engine, not by secrets-provider
// plugins.
func NewAuthorizerHandler(a clientresolver.Authorizer) resolverv1rpc.AuthorizerServiceHandler {
	return &authorizerService{a}
}

func (s authorizerService) Authorize(ctx context.Context, req *resolverv1.AuthorizeRequest) (*resolverv1.AuthorizeResponse, error) {
	msgPatterns := req.GetPatterns()
	if len(msgPatterns) == 0 {
		return nil, rpc.NewError(rpc.CodeInvalidArgument, errors.New("at least one pattern is required"))
	}
	patterns := make([]secrets.Pattern, 0, len(msgPatterns))
	for _, msgPattern := range msgPatterns {
		pattern, err := secrets.ParsePattern(msgPattern)
		if err != nil {
			return nil, rpc.NewError(rpc.CodeInvalidArgument, fmt.Errorf("invalid pattern %q: %w", msgPattern, err))
		}
		patterns = append(patterns, pattern)
	}

	resp, err := s.authorizer.Authorize(ctx, patterns...)
	if err != nil {
		if errors.Is(err, secrets.ErrAccessDenied) {
			return nil, rpc.NewError(rpc.CodePermissionDenied, secrets.ErrAccessDenied)
		}
		return nil, rpc.NewError(rpc.CodeInternal, fmt.Errorf("authorize failed for %q: %w", msgPatterns, err))
	}
	decision := resolverv1.Decision_DECISION_DENY
	if resp.Allow {
		decision = resolverv1.Decision_DECISION_ALLOW
	}
	// A zero Expiry means the decision never expires: leave the timestamp absent.
	var expiresAt *timestamppb.Timestamp
	if !resp.Expiry.IsZero() {
		expiresAt = timestamppb.New(resp.Expiry)
	}
	return resolverv1.AuthorizeResponse_builder{
		ExpiresAt: expiresAt,
		Decision:  &decision,
	}.Build(), nil
}

var _ clientresolver.Authorizer = &authorizerClient{}

type authorizerClient struct {
	client resolverv1rpc.AuthorizerServiceClient
}

func NewAuthorizerClient(httpClient rpc.HTTPClient) clientresolver.Authorizer {
	return &authorizerClient{client: resolverv1rpc.NewAuthorizerServiceClient(httpClient, "http://unix")}
}

func (a authorizerClient) Authorize(ctx context.Context, patterns ...secrets.Pattern) (clientresolver.AuthorizeResponse, error) {
	msgPatterns := make([]string, 0, len(patterns))
	for _, p := range patterns {
		msgPatterns = append(msgPatterns, p.String())
	}
	resp, err := a.client.Authorize(ctx, resolverv1.AuthorizeRequest_builder{
		Patterns: msgPatterns,
	}.Build())
	if err != nil {
		if rpc.CodeOf(err) == rpc.CodePermissionDenied {
			err = secrets.ErrAccessDenied
		}
		return clientresolver.AuthorizeResponse{}, err
	}

	// An absent timestamp means the decision never expires: keep the zero time.
	var expiry time.Time
	if resp.HasExpiresAt() {
		expiry = resp.GetExpiresAt().AsTime()
	}
	return clientresolver.AuthorizeResponse{
		Expiry: expiry,
		Allow:  resp.GetDecision() == resolverv1.Decision_DECISION_ALLOW,
	}, nil
}
