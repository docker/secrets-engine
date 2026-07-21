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
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"

	pluginsv1 "github.com/docker/secrets-engine/x/api/plugins/v1"
	"github.com/docker/secrets-engine/x/api/plugins/v1/pluginsv1connect"
)

var _ pluginsv1connect.PluginServiceHandler = &pluginService{}

type pluginService struct {
	shutdown func(context.Context)
}

func (s *pluginService) Shutdown(ctx context.Context, _ *connect.Request[pluginsv1.ShutdownRequest]) (*connect.Response[pluginsv1.ShutdownResponse], error) {
	s.shutdown(ctx)
	return connect.NewResponse(&pluginsv1.ShutdownResponse{}), nil
}

func setupInterceptor(chSetup chan struct{}, timeout time.Duration) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			// Fast path once setup is done: avoids allocating a timer per RPC.
			select {
			case <-chSetup:
				return next(ctx, req)
			default:
			}
			// Only reached while registration is still in progress.
			select {
			case <-chSetup:
				return next(ctx, req)
			case <-ctx.Done():
				return nil, connect.NewError(connect.CodeInternal, errors.New("context cancelled while waiting for registration"))
			case <-time.After(timeout):
				return nil, connect.NewError(connect.CodeDeadlineExceeded, fmt.Errorf("registration incomplete (timeout after %s)", timeout))
			}
		}
	}
}
