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

package dockerhub_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/client"
	"github.com/docker/secrets-engine/client/dockerhub"
	"github.com/docker/secrets-engine/client/trace"
	"github.com/docker/secrets-engine/x/secrets"
)

type spanKey struct{}

// ctxEngine records the span seen by each resolver call.
type ctxEngine struct {
	fakeEngine
	spans *[]any
}

func (e ctxEngine) GetSecrets(ctx context.Context, pattern secrets.Pattern) ([]secrets.Envelope, error) {
	*e.spans = append(*e.spans, ctx.Value(spanKey{}))
	return e.fakeEngine.GetSecrets(ctx, pattern)
}

type call struct {
	op   trace.Operation
	err  error
	span any
}

func recordingHooks(starts, dones *[]call) trace.Hooks {
	return trace.Hooks{
		Start: func(ctx context.Context, op trace.Operation) context.Context {
			span := fmt.Sprintf("span-%d", len(*starts))
			*starts = append(*starts, call{op: op, span: span})
			return context.WithValue(ctx, spanKey{}, span)
		},
		Done: func(ctx context.Context, op trace.Operation, err error) {
			*dones = append(*dones, call{op: op, err: err, span: ctx.Value(spanKey{})})
		},
	}
}

func TestWithHooks(t *testing.T) {
	t.Parallel()
	store := map[string]string{
		"docker/auth/hub/alice":            sessionWire,
		"docker/auth/metadata/hub/alice":   profileWire,
		"docker/auth/metadata/hub/default": profileWire,
	}
	var starts, dones []call
	var spans []any
	engine := ctxEngine{fakeEngine: serving(store), spans: &spans}
	auth := dockerhub.New(engine, dockerhub.WithHooks(recordingHooks(&starts, &dones)))
	ctx := t.Context()

	_, err := auth.ListProfiles(ctx)
	require.NoError(t, err)
	_, err = auth.GetDefaultProfile(ctx)
	require.NoError(t, err)
	_, err = auth.GetDefaultSession(ctx)
	require.NoError(t, err)
	_, err = auth.GetSession(ctx, "alice")
	require.NoError(t, err)
	_, err = auth.GetSession(ctx, "nobody")
	require.ErrorIs(t, err, dockerhub.ErrNoSession)

	op := func(name string) trace.Operation {
		return trace.Operation{Name: name, Realm: trace.RealmDockerHub}
	}
	wantOps := []trace.Operation{
		op(trace.OpDockerHubListProfiles),
		op(trace.OpDockerHubGetDefaultProfile),
		op(trace.OpDockerHubGetDefaultSession), // no nested GetDefaultProfile
		op(trace.OpDockerHubGetSession),
		op(trace.OpDockerHubGetSession),
	}
	require.Len(t, starts, len(wantOps))
	require.Len(t, dones, len(wantOps))
	for i, want := range wantOps {
		assert.Equal(t, want, starts[i].op)
		assert.Equal(t, want, dones[i].op)
		assert.Equal(t, starts[i].span, dones[i].span, "Done gets the ctx from Start")
	}
	for i := range 4 {
		assert.NoError(t, dones[i].err)
	}
	assert.Equal(t, client.ErrorKindNoSession, client.ErrorKind(dones[4].err))

	// Every resolver call ran under the ctx returned by Start: one call each
	// for the first two, two for GetDefaultSession, one each for GetSession.
	assert.Equal(t, []any{"span-0", "span-1", "span-2", "span-2", "span-3", "span-4"}, spans)

	for _, c := range append(starts, dones...) {
		seen := fmt.Sprintf("%+v %v", c.op, c.err)
		assert.NotContains(t, seen, "token-alice")
		assert.NotContains(t, seen, "alice")
	}
}

func TestWithHooks_Staging(t *testing.T) {
	t.Parallel()
	var starts, dones []call
	auth := dockerhub.New(serving(nil), dockerhub.Staging(), dockerhub.WithHooks(recordingHooks(&starts, &dones)))
	_, err := auth.GetDefaultSession(t.Context())
	require.ErrorIs(t, err, dockerhub.ErrNoDefaultProfile)
	require.Len(t, dones, 1)
	assert.Equal(t, trace.Operation{Name: trace.OpDockerHubGetDefaultSession, Realm: trace.RealmDockerHubStaging}, dones[0].op)
	assert.Equal(t, client.ErrorKindNoSession, client.ErrorKind(dones[0].err))
}

func TestWithHooks_Zero(t *testing.T) {
	t.Parallel()
	auth := dockerhub.New(serving(map[string]string{"docker/auth/hub/alice": sessionWire}), dockerhub.WithHooks(trace.Hooks{}))
	session, err := auth.GetSession(t.Context(), "alice")
	require.NoError(t, err)
	assert.Equal(t, "token-alice", session.AccessToken)
}
