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

package resolver

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	resolverv1 "github.com/docker/secrets-engine/x/api/resolver/v1"
	"github.com/docker/secrets-engine/x/secrets"
)

const (
	mockSecretValue = "mockSecretValue"
)

var (
	mockPattern  = secrets.MustParsePattern("**")
	mockID       = secrets.MustParseID("mockID")
	mockMetadata = map[string]string{
		"Test": "test",
	}
)

type mockResolver struct {
	t         *testing.T
	secretsID secrets.ID
	value     string
	err       error
	metadata  map[string]string
}

func newMockResolver(t *testing.T, options ...mockResolverOption) *mockResolver {
	resolver := &mockResolver{
		t:         t,
		secretsID: mockID,
		value:     mockSecretValue,
		metadata:  mockMetadata,
	}
	for _, opt := range options {
		resolver = opt(resolver)
	}
	return resolver
}

type mockResolverOption func(*mockResolver) *mockResolver

func withMockResolverError(err error) mockResolverOption {
	return func(m *mockResolver) *mockResolver {
		m.err = err
		return m
	}
}

func (m mockResolver) GetSecrets(_ context.Context, pattern secrets.Pattern) ([]secrets.Envelope, error) {
	if m.err != nil {
		return []secrets.Envelope{}, m.err
	}
	if pattern.Match(m.secretsID) {
		return []secrets.Envelope{{ID: m.secretsID, Value: []byte(m.value), Metadata: m.metadata}}, nil
	}
	return []secrets.Envelope{}, nil
}

func TestResolverService_GetSecret(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "returns an error if request secret ID is invalid",
			test: func(t *testing.T) {
				s := NewResolverHandler(newMockResolver(t))
				_, err := s.GetSecrets(t.Context(), newGetSecretRequest(&maliciousPattern{}))
				assert.ErrorContains(t, err, "invalid pattern")
			},
		},
		{
			name: "secret not found",
			test: func(t *testing.T) {
				s := NewResolverHandler(newMockResolver(t, withMockResolverError(secrets.ErrNotFound)))
				_, err := s.GetSecrets(t.Context(), newGetSecretRequest(mockPattern))
				assert.ErrorIs(t, err, secrets.ErrNotFound)
			},
		},
		{
			name: "error fetching secret",
			test: func(t *testing.T) {
				s := NewResolverHandler(newMockResolver(t, withMockResolverError(errors.New("foo"))))
				_, err := s.GetSecrets(t.Context(), newGetSecretRequest(mockPattern))
				assert.ErrorContains(t, err, "foo")
			},
		},
		{
			name: "no match",
			test: func(t *testing.T) {
				s := NewResolverHandler(newMockResolver(t))
				_, err := s.GetSecrets(t.Context(), newGetSecretRequest(secrets.MustParsePattern("not-existing")))
				assert.ErrorIs(t, err, secrets.ErrNotFound)
			},
		},
		{
			name: "returns secret value",
			test: func(t *testing.T) {
				s := NewResolverHandler(newMockResolver(t))
				resp, err := s.GetSecrets(t.Context(), newGetSecretRequest(mockPattern))
				assert.NoError(t, err)
				require.NotEmpty(t, resp.Msg.GetEnvelopes())
				assert.Equal(t, mockID.String(), resp.Msg.GetEnvelopes()[0].GetId())
				assert.Equal(t, mockSecretValue, string(resp.Msg.GetEnvelopes()[0].GetValue()))
			},
		},
		{
			name: "return secret metadata",
			test: func(t *testing.T) {
				s := NewResolverHandler(newMockResolver(t))
				resp, err := s.GetSecrets(t.Context(), newGetSecretRequest(mockPattern))
				assert.NoError(t, err)
				assert.Equal(t, mockID.String(), resp.Msg.GetEnvelopes()[0].GetId())
				assert.EqualValues(t, mockMetadata, resp.Msg.GetEnvelopes()[0].GetMetadata())
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.test(t)
		})
	}
}

type maliciousPattern struct{}

func (m maliciousPattern) Match(secrets.ID) bool {
	return false
}

func (m maliciousPattern) Includes(secrets.Pattern) bool {
	return false
}

type mockAuthorizer struct {
	called bool
	resp   secrets.AuthorizeResponse
	err    error
}

func (m *mockAuthorizer) Authorize(context.Context, ...secrets.Pattern) (secrets.AuthorizeResponse, error) {
	m.called = true
	return m.resp, m.err
}

func TestAuthorizerService_Authorize(t *testing.T) {
	t.Parallel()

	t.Run("rejects empty patterns", func(t *testing.T) {
		m := &mockAuthorizer{}
		s := NewAuthorizerHandler(m)
		_, err := s.Authorize(t.Context(), connect.NewRequest(resolverv1.AuthorizeRequest_builder{}.Build()))
		require.Error(t, err)
		assert.Equal(t, connect.CodeInvalidArgument, connect.CodeOf(err))
		assert.ErrorContains(t, err, "at least one pattern is required")
		assert.False(t, m.called, "authorizer must not run without a pattern")
	})

	t.Run("returns decision and expiry", func(t *testing.T) {
		expiry := time.Now().Add(time.Hour).UTC()
		s := NewAuthorizerHandler(&mockAuthorizer{resp: secrets.AuthorizeResponse{Expiry: expiry, Allow: true}})
		resp, err := s.Authorize(t.Context(), connect.NewRequest(resolverv1.AuthorizeRequest_builder{
			Patterns: []string{"docker/auth/hub/joe"},
		}.Build()))
		require.NoError(t, err)
		assert.True(t, resp.Msg.GetExpiresAt().AsTime().Equal(expiry), "expiry must round-trip")
		assert.Equal(t, resolverv1.Decision_DECISION_ALLOW, resp.Msg.GetDecision())
	})

	t.Run("returns a deny decision without an error", func(t *testing.T) {
		s := NewAuthorizerHandler(&mockAuthorizer{})
		resp, err := s.Authorize(t.Context(), connect.NewRequest(resolverv1.AuthorizeRequest_builder{
			Patterns: []string{"docker/auth/hub/joe"},
		}.Build()))
		require.NoError(t, err)
		assert.Equal(t, resolverv1.Decision_DECISION_DENY, resp.Msg.GetDecision())
	})

	t.Run("maps denial to permission denied", func(t *testing.T) {
		s := NewAuthorizerHandler(&mockAuthorizer{err: secrets.ErrAccessDenied})
		_, err := s.Authorize(t.Context(), connect.NewRequest(resolverv1.AuthorizeRequest_builder{
			Patterns: []string{"docker/auth/hub/joe"},
		}.Build()))
		require.Error(t, err)
		assert.Equal(t, connect.CodePermissionDenied, connect.CodeOf(err))
	})

	t.Run("wraps other errors as internal", func(t *testing.T) {
		s := NewAuthorizerHandler(&mockAuthorizer{err: errors.New("boom")})
		_, err := s.Authorize(t.Context(), connect.NewRequest(resolverv1.AuthorizeRequest_builder{
			Patterns: []string{"docker/auth/hub/joe"},
		}.Build()))
		require.Error(t, err)
		assert.Equal(t, connect.CodeInternal, connect.CodeOf(err))
	})
}

func (m maliciousPattern) String() string {
	return "/"
}

func (m maliciousPattern) ExpandID(secrets.ID) (secrets.ID, error) {
	panic("implement me")
}

func (m maliciousPattern) ExpandPattern(secrets.Pattern) (secrets.Pattern, error) {
	panic("implement me")
}

func newGetSecretRequest(pattern secrets.Pattern) *connect.Request[resolverv1.GetSecretsRequest] {
	return connect.NewRequest(resolverv1.GetSecretsRequest_builder{
		Pattern: proto.String(pattern.String()),
	}.Build())
}
