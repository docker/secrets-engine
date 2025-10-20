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
	Envelope = secrets.Envelope
	ID       = secrets.ID
	Pattern  = secrets.Pattern
)

var (
	ParseID     = secrets.ParseID
	MustParseID = secrets.MustParseID

	ParsePattern     = secrets.ParsePattern
	MustParsePattern = secrets.MustParsePattern

	ErrSecretNotFound = secrets.ErrNotFound
)

var _ secrets.Resolver = &client{}

type Option func(c *config) error

func WithSocketPath(path string) Option {
	return func(s *config) error {
		if path == "" {
			return errors.New("no path provided")
		}
		if s.dialContext != nil {
			return errors.New("cannot set socket path and dial")
		}
		s.dialContext = dialFromPath(path)
		return nil
	}
}

func WithDialContext(dialContext func(ctx context.Context, network, addr string) (net.Conn, error)) Option {
	return func(s *config) error {
		if s.dialContext != nil {
			return errors.New("cannot set socket path and dial")
		}
		s.dialContext = dialContext
		return nil
	}
}

func WithTimeout(timeout time.Duration) Option {
	return func(s *config) error {
		s.requestTimeout = timeout
		return nil
	}
}

type dial func(ctx context.Context, network, addr string) (net.Conn, error)

type config struct {
	dialContext    dial
	requestTimeout time.Duration
}

type client struct {
	resolverClient resolverv1connect.ResolverServiceClient
}

func New(options ...Option) (secrets.Resolver, error) {
	cfg := &config{
		requestTimeout: api.DefaultPluginRequestTimeout,
	}
	for _, opt := range options {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}
	if cfg.dialContext == nil {
		cfg.dialContext = dialFromPath(api.DefaultSocketPath())
	}
	c := &http.Client{
		Transport: &http.Transport{
			DialContext:        cfg.dialContext,
			DisableKeepAlives:  true,
			DisableCompression: true,
		},
		Timeout: cfg.requestTimeout,
	}
	return &client{
		resolverClient: resolverv1connect.NewResolverServiceClient(c, "http://unix"),
	}, nil
}

func (c client) GetSecrets(ctx context.Context, pattern secrets.Pattern) ([]secrets.Envelope, error) {
	req := connect.NewRequest(v1.GetSecretsRequest_builder{
		Pattern: proto.String(pattern.String()),
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

func dialFromPath(path string) dial {
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		d := &net.Dialer{}
		return d.DialContext(ctx, "unix", path)
	}
}
