package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	resolverv1 "github.com/docker/secrets-engine/internal/api/resolver/v1"
	"github.com/docker/secrets-engine/internal/api/resolver/v1/resolverv1connect"
	"github.com/docker/secrets-engine/internal/secrets"
)

var _ resolverv1connect.ResolverServiceHandler = &resolverService{}

type resolverService struct {
	resolver secrets.Resolver
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
	if envelope.ID != id {
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

var _ secrets.Resolver = &resolver{}

type resolver struct {
	reg registry
}

func (r resolver) GetSecret(ctx context.Context, req secrets.Request) (secrets.Envelope, error) {
	var errs []error

	if err := req.ID.Valid(); err != nil {
		return secrets.EnvelopeErr(req, err), err
	}

	for _, plugin := range r.reg.GetAll() {
		d := plugin.Data()
		if req.Provider != "" && req.Provider != d.name {
			continue
		}
		if !d.pattern.Match(req.ID) {
			continue
		}

		envelope, err := plugin.GetSecret(ctx, req)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		// we use the first matching, successful registration to resolve the secret.
		envelope.Provider = d.name

		if envelope.ResolvedAt.IsZero() {
			envelope.ResolvedAt = time.Now().UTC()
		}
		return envelope, nil
	}

	var err error
	if len(errs) == 0 {
		err = fmt.Errorf("secret %q: %w", req.ID, secrets.ErrNotFound)
	} else {
		err = errors.Join(errs...)
	}
	return secrets.EnvelopeErr(req, err), err
}
