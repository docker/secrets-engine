package resolver

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	resolverv1 "github.com/docker/secrets-engine/x/api/resolver/v1"
	"github.com/docker/secrets-engine/x/api/resolver/v1/resolverv1connect"
	"github.com/docker/secrets-engine/x/secrets"
)

var _ resolverv1connect.ResolverServiceHandler = &resolverService{}

type resolverService struct {
	resolver secrets.Resolver
}

func NewResolverHandler(r secrets.Resolver) resolverv1connect.ResolverServiceHandler {
	return &resolverService{r}
}

func (r resolverService) GetSecret(ctx context.Context, c *connect.Request[resolverv1.GetSecretRequest]) (*connect.Response[resolverv1.GetSecretResponse], error) {
	msgID := c.Msg.GetId()
	id, err := secrets.ParseID(msgID)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid secret ID %q: %w", msgID, err))
	}

	envelope, err := r.resolver.GetSecret(ctx, secrets.Request{ID: id, Provider: c.Msg.GetProvider()})
	if err != nil {
		if errors.Is(err, secrets.ErrNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("secret %q not found: %w", msgID, err))
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get secret %q: %w", msgID, err))
	}
	if envelope.ID.String() != id.String() {
		return nil, connect.NewError(connect.CodeInternal, secrets.ErrIDMismatch)
	}
	return connect.NewResponse(resolverv1.GetSecretResponse_builder{
		Id:         proto.String(envelope.ID.String()),
		Value:      envelope.Value,
		Provider:   proto.String(envelope.Provider),
		Version:    proto.String(envelope.Version),
		Error:      proto.String(envelope.Error),
		CreatedAt:  timestamppb.New(envelope.CreatedAt),
		ResolvedAt: timestamppb.New(envelope.ResolvedAt),
		ExpiresAt:  timestamppb.New(envelope.ExpiresAt),
	}.Build()), nil
}
