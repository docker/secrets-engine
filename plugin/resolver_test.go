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
	mockSecretPattern = secrets.MustParsePattern("mockSecretID")
	mockResponse      = connect.NewResponse(resolverv1.GetSecretResponse_builder{
		Envelopes: []*resolverv1.GetSecretResponse_Envelope{
			resolverv1.GetSecretResponse_Envelope_builder{Id: proto.String("mockSecretID")}.Build(),
		},
	}.Build())
)

var _ resolverv1connect.ResolverServiceHandler = &mockHandler{}

type mockHandler struct {
	getSecretCalled int
}

func (m *mockHandler) GetSecrets(context.Context, *connect.Request[resolverv1.GetSecretRequest]) (*connect.Response[resolverv1.GetSecretResponse], error) {
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
				_, err := s.GetSecrets(t.Context(), newGetSecretRequest(mockSecretPattern))
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
				resp, err := s.GetSecrets(t.Context(), newGetSecretRequest(mockSecretPattern))
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

func newGetSecretRequest(pattern secrets.Pattern) *connect.Request[resolverv1.GetSecretRequest] {
	return connect.NewRequest(resolverv1.GetSecretRequest_builder{
		Pattern: proto.String(pattern.String()),
	}.Build())
}
