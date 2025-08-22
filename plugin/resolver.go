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

func (r *resolverService) GetSecrets(ctx context.Context, c *connect.Request[resolverv1.GetSecretRequest]) (*connect.Response[resolverv1.GetSecretResponse], error) {
	select {
	case <-r.setupCompleted:
	case <-ctx.Done():
		return nil, connect.NewError(connect.CodeInternal, errors.New("context cancelled while waiting for registration"))
	case <-time.After(r.registrationTimeout):
		return nil, connect.NewError(connect.CodeDeadlineExceeded, fmt.Errorf("registration incomplete (timeout after %s)", r.registrationTimeout))
	}
	return r.handler.GetSecrets(ctx, c)
}
