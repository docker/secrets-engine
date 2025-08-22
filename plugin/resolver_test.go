package plugin

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"

	resolverv1 "github.com/docker/secrets-engine/x/api/resolver/v1"
	"github.com/docker/secrets-engine/x/api/resolver/v1/resolverv1connect"
	"github.com/docker/secrets-engine/x/secrets"
)

var (
	mockSecretIDNew = secrets.MustParseID("mockSecretID")
	mockResponse    = connect.NewResponse(resolverv1.GetSecretResponse_builder{
		Id: proto.String("mockSecretID"),
	}.Build())
)

var _ resolverv1connect.ResolverServiceHandler = &mockHandler{}

type mockHandler struct {
	getSecretCalled int
}

func (m *mockHandler) GetSecret(context.Context, *connect.Request[resolverv1.GetSecretRequest]) (*connect.Response[resolverv1.GetSecretResponse], error) {
	m.getSecretCalled++
	return mockResponse, nil
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
				m := &mockHandler{}
				s := &resolverService{handler: m}
				_, err := s.GetSecret(t.Context(), newGetSecretRequest(mockSecretIDNew))
				assert.ErrorContains(t, err, "registration incomplete (timeout ")
				assert.Equal(t, 0, m.getSecretCalled)
			},
		},
		{
			name: "returns secret value",
			test: func(t *testing.T) {
				m := &mockHandler{}
				done := make(chan struct{})
				close(done)
				s := &resolverService{handler: m, setupCompleted: done, registrationTimeout: 10 * time.Second}
				resp, err := s.GetSecret(t.Context(), newGetSecretRequest(mockSecretIDNew))
				assert.NoError(t, err)
				assert.Equal(t, resp, mockResponse)
				assert.Equal(t, 1, m.getSecretCalled)
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
		Id: proto.String(secretID.String()),
	}.Build())
}
