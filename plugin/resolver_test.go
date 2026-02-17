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
	mockResponse      = connect.NewResponse(resolverv1.GetSecretsResponse_builder{
		Envelopes: []*resolverv1.GetSecretsResponse_Envelope{
			resolverv1.GetSecretsResponse_Envelope_builder{Id: proto.String("mockSecretID")}.Build(),
		},
	}.Build())
)

var _ resolverv1connect.ResolverServiceHandler = &mockHandler{}

type mockHandler struct {
	getSecretCalled int
}

func (m *mockHandler) GetSecrets(context.Context, *connect.Request[resolverv1.GetSecretsRequest]) (*connect.Response[resolverv1.GetSecretsResponse], error) {
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

func newGetSecretRequest(pattern secrets.Pattern) *connect.Request[resolverv1.GetSecretsRequest] {
	return connect.NewRequest(resolverv1.GetSecretsRequest_builder{
		Pattern: proto.String(pattern.String()),
	}.Build())
}
