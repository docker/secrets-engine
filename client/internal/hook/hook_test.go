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

package hook

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/client/trace"
)

type ctxKey struct{}

func TestStartZeroHooksAllocatesNothing(t *testing.T) {
	ctx := t.Context()
	op := trace.Operation{Name: trace.OpResolverGetSecrets}
	allocs := testing.AllocsPerRun(100, func() {
		got, done := Start(ctx, trace.Hooks{}, op)
		done(nil)
		if got != ctx {
			t.Fatal("context changed")
		}
	})
	assert.Zero(t, allocs)
	assert.False(t, Enabled(trace.Hooks{}))
}

func TestStartNilContextFromStartKeepsOriginal(t *testing.T) {
	ctx := t.Context()
	got, done := Start(ctx, trace.Hooks{
		Start: func(context.Context, trace.Operation) context.Context { return nil },
	}, trace.Operation{})
	done(nil)
	assert.Equal(t, ctx, got)
}

func TestStartPassesDerivedContextToDone(t *testing.T) {
	var doneCtx context.Context
	var doneErr error
	wantErr := errors.New("boom")
	h := trace.Hooks{
		Start: func(ctx context.Context, _ trace.Operation) context.Context {
			return context.WithValue(ctx, ctxKey{}, "span")
		},
		Done: func(ctx context.Context, _ trace.Operation, err error) {
			doneCtx, doneErr = ctx, err
		},
	}
	require.True(t, Enabled(h))
	ctx, done := Start(t.Context(), h, trace.Operation{})
	assert.Equal(t, "span", ctx.Value(ctxKey{}))
	done(wantErr)
	assert.Equal(t, "span", doneCtx.Value(ctxKey{}))
	assert.Equal(t, wantErr, doneErr)
}

func TestMalformed(t *testing.T) {
	assert.NoError(t, Malformed(nil))
	inner := errors.New("decode: bad")
	err := Malformed(inner)
	assert.Equal(t, inner.Error(), err.Error(), "message is preserved")
	assert.ErrorIs(t, err, inner)
}
