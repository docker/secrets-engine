package resolver

import (
	"context"
	"errors"
	"testing"

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

var mockSecretIDNew = secrets.MustParsePattern("**")

type mockResolver struct {
	t         *testing.T
	secretsID string
	value     string
	err       error
}

func newMockResolver(t *testing.T, options ...mockResolverOption) *mockResolver {
	resolver := &mockResolver{
		t:         t,
		secretsID: mockSecretIDNew.String(),
		value:     mockSecretValue,
	}
	for _, opt := range options {
		resolver = opt(resolver)
	}
	return resolver
}

type mockResolverOption func(*mockResolver) *mockResolver

func withMockResolverID(id string) mockResolverOption {
	return func(m *mockResolver) *mockResolver {
		m.secretsID = id
		return m
	}
}

func withMockResolverError(err error) mockResolverOption {
	return func(m *mockResolver) *mockResolver {
		m.err = err
		return m
	}
}

func (m mockResolver) GetSecrets(context.Context, secrets.Request) ([]secrets.Envelope, error) {
	if m.err != nil {
		return []secrets.Envelope{}, m.err
	}
	return []secrets.Envelope{
		{
			ID:    secrets.MustParseID(m.secretsID),
			Value: []byte(m.value),
		},
	}, nil
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
				assert.ErrorContains(t, err, "invalid secret ID")
			},
		},
		{
			name: "secret not found",
			test: func(t *testing.T) {
				s := NewResolverHandler(newMockResolver(t, withMockResolverError(secrets.ErrNotFound)))
				_, err := s.GetSecrets(t.Context(), newGetSecretRequest(mockSecretIDNew))
				assert.ErrorIs(t, err, secrets.ErrNotFound)
			},
		},
		{
			name: "error fetching secret",
			test: func(t *testing.T) {
				s := NewResolverHandler(newMockResolver(t, withMockResolverError(errors.New("foo"))))
				_, err := s.GetSecrets(t.Context(), newGetSecretRequest(mockSecretIDNew))
				assert.ErrorContains(t, err, "foo")
			},
		},
		{
			name: "returns wrong ID",
			test: func(t *testing.T) {
				s := NewResolverHandler(newMockResolver(t, withMockResolverID("wrongID")))
				_, err := s.GetSecrets(t.Context(), newGetSecretRequest(mockSecretIDNew))
				assert.ErrorIs(t, err, secrets.ErrIDMismatch)
			},
		},
		{
			name: "returns secret value",
			test: func(t *testing.T) {
				s := NewResolverHandler(newMockResolver(t))
				resp, err := s.GetSecrets(t.Context(), newGetSecretRequest(mockSecretIDNew))
				assert.NoError(t, err)
				require.NotEmpty(t, resp.Msg.GetEnvelopes())
				assert.Equal(t, mockSecretIDNew.String(), resp.Msg.GetEnvelopes()[0].GetId())
				assert.Equal(t, mockSecretValue, string(resp.Msg.GetEnvelopes()[0].GetValue()))
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

func (m maliciousPattern) String() string {
	return "/"
}

func newGetSecretRequest(pattern secrets.Pattern) *connect.Request[resolverv1.GetSecretRequest] {
	return connect.NewRequest(resolverv1.GetSecretRequest_builder{
		Pattern: proto.String(pattern.String()),
	}.Build())
}
