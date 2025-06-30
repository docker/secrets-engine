package plugin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"

	resolverv1 "github.com/docker/secrets-engine/pkg/api/resolver/v1"
	"github.com/docker/secrets-engine/pkg/api/resolver/v1/resolverv1connect"
	"github.com/docker/secrets-engine/pkg/secrets"
)

var _ resolverv1connect.ResolverServiceHandler = &resolverService{}

type resolverService struct {
	resolver            secrets.Resolver
	setupCompleted      chan struct{}
	registrationTimeout time.Duration
}

func (r *resolverService) GetSecret(ctx context.Context, c *connect.Request[resolverv1.GetSecretRequest]) (*connect.Response[resolverv1.GetSecretResponse], error) {
	logrus.Debugf("GetSecret request (ID %q)", c.Msg.GetSecretId())
	select {
	case <-r.setupCompleted:
	case <-ctx.Done():
		return nil, connect.NewError(connect.CodeInternal, errors.New("context cancelled while waiting for registration"))
	case <-time.After(r.registrationTimeout):
		return nil, connect.NewError(connect.CodeDeadlineExceeded, fmt.Errorf("registration incomplete (timeout after %s)", r.registrationTimeout))
	}
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
	if envelope.ID != id {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("secret ID mismatch: expected %q, got %q", id, envelope.ID))
	}
	return connect.NewResponse(resolverv1.GetSecretResponse_builder{
		SecretId:    proto.String(envelope.ID.String()),
		SecretValue: proto.String(string(envelope.Value)),
	}.Build()), nil
}
