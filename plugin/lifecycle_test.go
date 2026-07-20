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

package plugin

import (
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
)

func TestSetupInterceptor(t *testing.T) {
	t.Parallel()
	newNext := func(called *int) connect.UnaryFunc {
		return func(context.Context, connect.AnyRequest) (connect.AnyResponse, error) {
			*called++
			return nil, nil
		}
	}

	tests := []struct {
		name        string
		chSetup     func() chan struct{}
		timeout     time.Duration
		ctx         func() context.Context
		wantCalled  int
		errContains string
	}{
		{
			name: "delegates once setup completed",
			chSetup: func() chan struct{} {
				done := make(chan struct{})
				close(done)
				return done
			},
			timeout:    10 * time.Second,
			ctx:        t.Context,
			wantCalled: 1,
		},
		{
			name:        "fails when registration times out",
			chSetup:     func() chan struct{} { return make(chan struct{}) },
			timeout:     0,
			ctx:         t.Context,
			errContains: "registration incomplete (timeout ",
		},
		{
			name:    "fails when context cancelled",
			chSetup: func() chan struct{} { return make(chan struct{}) },
			timeout: 10 * time.Second,
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				return ctx
			},
			errContains: "context cancelled while waiting for registration",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			called := 0
			interceptor := setupInterceptor(tt.chSetup(), tt.timeout)
			_, err := interceptor(newNext(&called))(tt.ctx(), nil)
			if tt.errContains == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tt.errContains)
			}
			assert.Equal(t, tt.wantCalled, called)
		})
	}
}
