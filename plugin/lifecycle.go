package plugin

import (
	"context"

	"connectrpc.com/connect"

	resolverv1 "github.com/docker/secrets-engine/x/api/resolver/v1"
	"github.com/docker/secrets-engine/x/api/resolver/v1/resolverv1connect"
)

var _ resolverv1connect.PluginServiceHandler = &pluginService{}

type pluginService struct {
	shutdown func(context.Context)
}

func (s *pluginService) Shutdown(ctx context.Context, _ *connect.Request[resolverv1.ShutdownRequest]) (*connect.Response[resolverv1.ShutdownResponse], error) {
	s.shutdown(ctx)
	return connect.NewResponse(&resolverv1.ShutdownResponse{}), nil
}
