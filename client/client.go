package client

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	"github.com/docker/secrets-engine/internal/api"
	v1 "github.com/docker/secrets-engine/internal/api/resolver/v1"
	"github.com/docker/secrets-engine/internal/api/resolver/v1/resolverv1connect"
	"github.com/docker/secrets-engine/internal/secrets"
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

func (c client) GetSecret(ctx context.Context, request secrets.Request) (secrets.Envelope, error) {
	req := connect.NewRequest(v1.GetSecretRequest_builder{
		Id:       proto.String(request.ID.String()),
		Provider: proto.String(request.Provider),
	}.Build())
	resp, err := c.resolverClient.GetSecret(ctx, req)
	if err != nil {
		if connect.CodeOf(err) == connect.CodeNotFound {
			err = secrets.ErrNotFound
		}
		return secrets.EnvelopeErr(request, err), err
	}
	id, err := secrets.ParseID(resp.Msg.GetId())
	if err != nil {
		return secrets.EnvelopeErr(request, err), err
	}
	e := secrets.Envelope{
		ID:         id,
		Value:      resp.Msg.GetValue(),
		Provider:   resp.Msg.GetProvider(),
		Version:    resp.Msg.GetVersion(),
		Error:      resp.Msg.GetError(),
		CreatedAt:  resp.Msg.GetCreatedAt().AsTime(),
		ResolvedAt: resp.Msg.GetResolvedAt().AsTime(),
		ExpiresAt:  resp.Msg.GetExpiresAt().AsTime(),
	}
	if e.Error != "" {
		return e, errors.New(e.Error)
	}
	return e, nil
}
