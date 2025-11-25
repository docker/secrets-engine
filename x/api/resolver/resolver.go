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

func (r resolverService) GetSecrets(ctx context.Context, c *connect.Request[resolverv1.GetSecretsRequest]) (*connect.Response[resolverv1.GetSecretsResponse], error) {
	msgPattern := c.Msg.GetPattern()
	pattern, err := secrets.ParsePattern(msgPattern)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid pattern %q: %w", msgPattern, err))
	}

	envelopes, err := r.resolver.GetSecrets(ctx, pattern)
	if err != nil {
		if errors.Is(err, secrets.ErrNotFound) {
			return nil, connect.NewError(connect.CodeNotFound, secrets.ErrNotFound)
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to get secret %q: %w", msgPattern, err))
	}
	if len(envelopes) == 0 {
		return nil, connect.NewError(connect.CodeNotFound, secrets.ErrNotFound)
	}
	var items []*resolverv1.GetSecretsResponse_Envelope
	for _, envelope := range envelopes {
		items = append(items, resolverv1.GetSecretsResponse_Envelope_builder{
			Id:         proto.String(envelope.ID.String()),
			Value:      envelope.Value,
			Metadata:   envelope.Metadata,
			Provider:   proto.String(envelope.Provider),
			Version:    proto.String(envelope.Version),
			CreatedAt:  timestamppb.New(envelope.CreatedAt),
			ResolvedAt: timestamppb.New(envelope.ResolvedAt),
			ExpiresAt:  timestamppb.New(envelope.ExpiresAt),
		}.Build())
	}
	return connect.NewResponse(resolverv1.GetSecretsResponse_builder{
		Envelopes: items,
	}.Build()), nil
}
