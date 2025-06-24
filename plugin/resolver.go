package plugin

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	resolverv1 "github.com/docker/secrets-engine/pkg/api/resolver/v1"
	"github.com/docker/secrets-engine/pkg/api/resolver/v1/resolverv1connect"
	"github.com/docker/secrets-engine/pkg/secrets"
)

var _ resolverv1connect.ResolverServiceHandler = &resolverService{}

type resolverService struct {
	resolver secrets.Resolver
}

func (r *resolverService) GetSecret(ctx context.Context, c *connect.Request[resolverv1.GetSecretRequest]) (*connect.Response[resolverv1.GetSecretResponse], error) {
	msgID := c.Msg.GetSecretId()
	id, err := secrets.ParseID(msgID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid secret ID %q: %w", msgID, err))
	}

	envelope, err := r.resolver.GetSecret(ctx, secrets.Request{ID: id})
	if err != nil {
		if errors.Is(err, secrets.ErrNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("secret %q not found: %w", msgID, err))
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get secret %q: %w", msgID, err))
	}
	return connect.NewResponse(resolverv1.GetSecretResponse_builder{
		SecretId:    proto.String(envelope.ID.String()),
		SecretValue: proto.String(string(envelope.Value)),
	}.Build()), nil
}
