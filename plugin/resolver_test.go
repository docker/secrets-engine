package plugin

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"

	resolverv1 "github.com/docker/secrets-engine/pkg/api/resolver/v1"
	"github.com/docker/secrets-engine/pkg/secrets"
)

const (
	mockSecretValue = "mockSecretValue"
	mockSecretID    = secrets.ID("mockSecretID")
)

type mockResolver struct {
	t     *testing.T
	id    secrets.ID
	value string
	err   error
}

func newMockResolver(t *testing.T, options ...mockResolverOption) *mockResolver {
	resolver := &mockResolver{
		t:     t,
		id:    mockSecretID,
		value: mockSecretValue,
	}
	for _, opt := range options {
		resolver = opt(resolver)
	}
	return resolver
}

type mockResolverOption func(*mockResolver) *mockResolver

func withMockResolverID(id secrets.ID) mockResolverOption {
	return func(m *mockResolver) *mockResolver {
		m.id = id
		return m
	}
}

func withMockResolverError(err error) mockResolverOption {
	return func(m *mockResolver) *mockResolver {
		m.err = err
		return m
	}
}

func (m mockResolver) GetSecret(_ context.Context, request secrets.Request) (secrets.Envelope, error) {
	if request.ID != mockSecretID {
		return secrets.Envelope{}, errors.New("unexpected secret ID")
	}
	if m.err != nil {
		return secrets.Envelope{}, m.err
	}
	return secrets.Envelope{
		ID:    m.id,
		Value: []byte(m.value),
	}, nil
}

func TestResolverService_GetSecret(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "does not resolve secrets before setup completed",
			test: func(t *testing.T) {
				s := &resolverService{resolver: newMockResolver(t)}
				_, err := s.GetSecret(t.Context(), newGetSecretRequest(mockSecretID))
				assert.ErrorContains(t, err, "registration incomplete (timeout ")
			},
		},
		{
			name: "returns an error if request secret ID is invalid",
			test: func(t *testing.T) {
				done := make(chan struct{})
				close(done)
				s := &resolverService{resolver: newMockResolver(t), setupCompleted: done, registrationTimeout: 10 * time.Second}
				_, err := s.GetSecret(t.Context(), newGetSecretRequest("/"))
				assert.ErrorContains(t, err, "invalid secret ID")
			},
		},
		{
			name: "secret not found",
			test: func(t *testing.T) {
				done := make(chan struct{})
				close(done)
				s := &resolverService{resolver: newMockResolver(t, withMockResolverError(secrets.ErrNotFound)), setupCompleted: done, registrationTimeout: 10 * time.Second}
				_, err := s.GetSecret(t.Context(), newGetSecretRequest(mockSecretID))
				assert.ErrorIs(t, err, secrets.ErrNotFound)
			},
		},
		{
			name: "error fetching secret",
			test: func(t *testing.T) {
				done := make(chan struct{})
				close(done)
				s := &resolverService{resolver: newMockResolver(t, withMockResolverError(errors.New("foo"))), setupCompleted: done, registrationTimeout: 10 * time.Second}
				_, err := s.GetSecret(t.Context(), newGetSecretRequest(mockSecretID))
				assert.ErrorContains(t, err, "foo")
			},
		},
		{
			name: "returns wrong ID",
			test: func(t *testing.T) {
				done := make(chan struct{})
				close(done)
				s := &resolverService{resolver: newMockResolver(t, withMockResolverID("wrongID")), setupCompleted: done, registrationTimeout: 10 * time.Second}
				_, err := s.GetSecret(t.Context(), newGetSecretRequest(mockSecretID))
				assert.ErrorIs(t, err, secrets.ErrIDMismatch)
			},
		},
		{
			name: "returns secret value",
			test: func(t *testing.T) {
				done := make(chan struct{})
				close(done)
				s := &resolverService{resolver: newMockResolver(t), setupCompleted: done, registrationTimeout: 10 * time.Second}
				resp, err := s.GetSecret(t.Context(), newGetSecretRequest(mockSecretID))
				assert.NoError(t, err)
				assert.Equal(t, mockSecretID.String(), resp.Msg.GetSecretId())
				assert.Equal(t, mockSecretValue, resp.Msg.GetSecretValue())
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			tt.test(t)
		})
	}
}

func newGetSecretRequest(secretID secrets.ID) *connect.Request[resolverv1.GetSecretRequest] {
	return connect.NewRequest(resolverv1.GetSecretRequest_builder{
		SecretId: proto.String(string(secretID)),
	}.Build())
}
