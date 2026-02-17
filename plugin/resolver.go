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

	resolverv1 "github.com/docker/secrets-engine/x/api/resolver/v1"
	"github.com/docker/secrets-engine/x/api/resolver/v1/resolverv1connect"
)

var _ resolverv1connect.ResolverServiceHandler = &resolverService{}

type resolverService struct {
	handler             resolverv1connect.ResolverServiceHandler
	setupCompleted      chan struct{}
	registrationTimeout time.Duration
}

func (r *resolverService) GetSecrets(ctx context.Context, c *connect.Request[resolverv1.GetSecretsRequest]) (*connect.Response[resolverv1.GetSecretsResponse], error) {
	select {
	case <-r.setupCompleted:
	case <-ctx.Done():
		return nil, connect.NewError(connect.CodeInternal, errors.New("context cancelled while waiting for registration"))
	case <-time.After(r.registrationTimeout):
		return nil, connect.NewError(connect.CodeDeadlineExceeded, fmt.Errorf("registration incomplete (timeout after %s)", r.registrationTimeout))
	}
	return r.handler.GetSecrets(ctx, c)
}
