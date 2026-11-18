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

	"google.golang.org/protobuf/proto"

	pluginsv1 "github.com/docker/secrets-engine/plugin/api/plugins/v1"
	"github.com/docker/secrets-engine/plugin/api/plugins/v1/pluginsv1rpc"
	"github.com/docker/secrets-engine/plugin/rpc"
)

var _ pluginsv1rpc.PluginServiceHandler = &pluginService{}

type pluginService struct {
	shutdown func(context.Context)
}

func (s *pluginService) Shutdown(ctx context.Context, _ *pluginsv1.ShutdownRequest) (*pluginsv1.ShutdownResponse, error) {
	s.shutdown(ctx)
	return &pluginsv1.ShutdownResponse{}, nil
}

func setupInterceptor(chSetup chan struct{}, timeout time.Duration) rpc.Interceptor {
	return func(next rpc.UnaryFunc) rpc.UnaryFunc {
		return func(ctx context.Context, req proto.Message) (proto.Message, error) {
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
				return nil, rpc.NewError(rpc.CodeInternal, errors.New("context cancelled while waiting for registration"))
			case <-time.After(timeout):
				return nil, rpc.NewError(rpc.CodeDeadlineExceeded, fmt.Errorf("registration incomplete (timeout after %s)", timeout))
			}
		}
	}
}
