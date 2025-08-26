package client

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	"github.com/docker/secrets-engine/x/api"
	v1 "github.com/docker/secrets-engine/x/api/resolver/v1"
	"github.com/docker/secrets-engine/x/api/resolver/v1/resolverv1connect"
	"github.com/docker/secrets-engine/x/secrets"
)

type (
	Request  = secrets.Request
	Envelope = secrets.Envelope
	ID       = secrets.ID
)

var _ secrets.Resolver = &client{}

type Option func(c *config) error

func WithSocketPath(path string) Option {
	return func(s *config) error {
		if path == "" {
			return errors.New("no path provided")
		}
		s.socketPath = path
		return nil
	}
}

func WithTimeout(timeout time.Duration) Option {
	return func(s *config) error {
		s.requestTimeout = timeout
		return nil
	}
}

type config struct {
	socketPath     string
	requestTimeout time.Duration
}

type client struct {
	resolverClient resolverv1connect.ResolverServiceClient
}

func New(options ...Option) (secrets.Resolver, error) {
	cfg := &config{
		socketPath:     api.DefaultSocketPath(),
		requestTimeout: api.DefaultPluginRequestTimeout,
	}
	for _, opt := range options {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}
	c := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				d := &net.Dialer{}
				return d.DialContext(ctx, "unix", cfg.socketPath)
			},
			DisableKeepAlives:  true,
			DisableCompression: true,
		},
		Timeout: cfg.requestTimeout,
	}
	return &client{
		resolverClient: resolverv1connect.NewResolverServiceClient(c, "http://unix"),
	}, nil
}

func (c client) GetSecrets(ctx context.Context, request secrets.Request) ([]secrets.Envelope, error) {
	req := connect.NewRequest(v1.GetSecretsRequest_builder{
		Pattern:  proto.String(request.Pattern.String()),
		Provider: proto.String(request.Provider),
	}.Build())
	resp, err := c.resolverClient.GetSecrets(ctx, req)
	if err != nil {
		if connect.CodeOf(err) == connect.CodeNotFound {
			err = secrets.ErrNotFound
		}
		return nil, err
	}

	var envelopes []secrets.Envelope
	for _, item := range resp.Msg.GetEnvelopes() {
		id, err := secrets.ParseID(item.GetId())
		if err != nil {
			continue
		}
		envelopes = append(envelopes, secrets.Envelope{
			ID:         id,
			Value:      item.GetValue(),
			Provider:   item.GetProvider(),
			Version:    item.GetVersion(),
			CreatedAt:  item.GetCreatedAt().AsTime(),
			ResolvedAt: item.GetResolvedAt().AsTime(),
			ExpiresAt:  item.GetExpiresAt().AsTime(),
		})
	}
	return envelopes, nil
}
