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

package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/client/dockerhub"
	"github.com/docker/secrets-engine/client/internal/hook"
	"github.com/docker/secrets-engine/x/secrets"
)

type timeoutErr struct{}

func (timeoutErr) Error() string { return "i/o timeout" }
func (timeoutErr) Timeout() bool { return true }

func wrap(err error) error { return fmt.Errorf("outer: %w", err) }

func TestErrorKind(t *testing.T) {
	malformed := hook.Malformed(errors.New("decode user session: bad"))
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ""},
		{"engine unavailable", fmt.Errorf("%w: %w", ErrSecretsEngineNotAvailable, &net.OpError{Op: "dial"}), ErrorKindEngineUnavailable},
		{"engine unavailable wrapped", wrap(ErrSecretsEngineNotAvailable), ErrorKindEngineUnavailable},
		{"raw dial error", wrap(&net.OpError{Op: "dial", Err: errors.New("connection refused")}), ErrorKindEngineUnavailable},
		{"canceled", wrap(context.Canceled), ErrorKindCanceled},
		{"connect canceled", connect.NewError(connect.CodeCanceled, errors.New("x")), ErrorKindCanceled},
		{"deadline", wrap(context.DeadlineExceeded), ErrorKindTimeout},
		{"connect deadline", wrap(connect.NewError(connect.CodeDeadlineExceeded, errors.New("x"))), ErrorKindTimeout},
		{"net timeout", wrap(timeoutErr{}), ErrorKindTimeout},
		{"no session", dockerhub.ErrNoSession, ErrorKindNoSession},
		{"no default profile", dockerhub.ErrNoDefaultProfile, ErrorKindNoSession},
		{"no session wrapped", wrap(dockerhub.ErrNoSession), ErrorKindNoSession},
		{"access denied", wrap(ErrAccessDenied), ErrorKindAccessDenied},
		{"connect permission denied", connect.NewError(connect.CodePermissionDenied, errors.New("x")), ErrorKindAccessDenied},
		{"not found", wrap(ErrSecretNotFound), ErrorKindNotFound},
		{"secrets not found", secrets.ErrNotFound, ErrorKindNotFound},
		{"connect not found", connect.NewError(connect.CodeNotFound, errors.New("x")), ErrorKindNotFound},
		{"malformed", malformed, ErrorKindParse},
		{"malformed wrapped", wrap(malformed), ErrorKindParse},
		{"malformed joined", errors.Join(malformed, hook.Malformed(errors.New("other"))), ErrorKindParse},
		{"other", errors.New("boom"), ErrorKindOther},
		{"connect internal", connect.NewError(connect.CodeInternal, errors.New("x")), ErrorKindOther},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ErrorKind(tt.err))
		})
	}
}

type staticResolver []secrets.Envelope

func (s staticResolver) GetSecrets(context.Context, secrets.Pattern) ([]secrets.Envelope, error) {
	return s, nil
}

func TestErrorKind_RealErrors(t *testing.T) {
	ctx := t.Context()
	t.Run("dockerhub decode errors are parse errors", func(t *testing.T) {
		hub := dockerhub.New(staticResolver{{Value: []byte("not json")}})
		_, err := hub.GetDefaultProfile(ctx)
		require.ErrorContains(t, err, "decode profile metadata")
		assert.Equal(t, ErrorKindParse, ErrorKind(err))

		_, err = hub.GetSession(ctx, "alice")
		require.ErrorContains(t, err, "decode user session")
		assert.Equal(t, ErrorKindParse, ErrorKind(err))

		_, err = hub.ListProfiles(ctx)
		assert.Equal(t, ErrorKindParse, ErrorKind(err))
	})
	t.Run("tampered default profile is a parse error", func(t *testing.T) {
		hub := dockerhub.New(staticResolver{{Value: []byte(`{"user_id":"acme/other"}`)}})
		_, err := hub.GetDefaultSession(ctx)
		require.Error(t, err)
		assert.Equal(t, ErrorKindParse, ErrorKind(err))
	})
	t.Run("missing default profile", func(t *testing.T) {
		hub := dockerhub.New(staticResolver{})
		_, err := hub.GetDefaultSession(ctx)
		assert.Equal(t, ErrorKindNoSession, ErrorKind(err))
	})
	t.Run("invalid daemon version is a parse error", func(t *testing.T) {
		socket := mockVersionEngine(t, "not a version", "", "")
		c, err := New(WithSocketPath(socket))
		require.NoError(t, err)
		_, err = c.Version(ctx)
		require.ErrorContains(t, err, "parsing daemon version")
		assert.Equal(t, ErrorKindParse, ErrorKind(err))
	})
}
