package client

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"connectrpc.com/connect"

	"github.com/docker/secrets-engine/x/api"
	"github.com/docker/secrets-engine/x/api/resolver"
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
	resolverClient secrets.Resolver
	listClient     resolverv1connect.ListServiceClient
}

func (c client) GetSecrets(ctx context.Context, pattern secrets.Pattern) ([]secrets.Envelope, error) {
	return c.resolverClient.GetSecrets(ctx, pattern)
}

type Client interface {
	secrets.Resolver

	ListPlugins(ctx context.Context) ([]PluginInfo, error)
}

func New(options ...Option) (Client, error) {
	cfg := &config{
		requestTimeout: api.DefaultClientRequestTimeout,
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
			// re-use the same connection to the engine, this speeds up subsequent
			// calls.
			MaxConnsPerHost:     api.DefaultClientMaxConnsPerHost,
			MaxIdleConnsPerHost: api.DefaultClientMaxIdleConnsPerHost,
			// keep the connection alive (good for long-lived clients)
			IdleConnTimeout: api.DefaultClientIdleConnTimeout,
			// Set short timeouts on headers
			ResponseHeaderTimeout: api.DefaultClientResponseHeaderTimeout,
			TLSHandshakeTimeout:   api.DefaultClientTLSHandshakeTimeout,

			DialContext:        cfg.dialContext,
			DisableKeepAlives:  false,
			DisableCompression: false,
			ForceAttemptHTTP2:  true,
		},
		// by default Timeout will be 0 (meaning no timeout)
		// it can be overwritten with [WithTimeout]
		Timeout: cfg.requestTimeout,
	}
	return &client{
		resolverClient: resolver.NewResolverClient(c),
		listClient:     resolverv1connect.NewListServiceClient(c, "http://unix"),
	}, nil
}

func (c client) ListPlugins(ctx context.Context) ([]PluginInfo, error) {
	req := connect.NewRequest(v1.ListPluginsRequest_builder{}.Build())
	resp, err := c.listClient.ListPlugins(ctx, req)
	if err != nil {
		return nil, err
	}
	var result []PluginInfo
	for _, item := range resp.Msg.GetPlugins() {
		name, err := api.NewName(item.GetName())
		if err != nil {
			continue
		}
		version, err := api.NewVersion(item.GetVersion())
		if err != nil {
			continue
		}
		pattern, err := secrets.ParsePattern(item.GetPattern())
		if err != nil {
			continue
		}
		result = append(result, PluginInfo{
			Name:     name,
			Version:  version,
			Pattern:  pattern,
			External: item.GetExternal(),
		})
	}
	return result, nil
}

type PluginInfo struct {
	Name     api.Name
	Version  api.Version
	Pattern  secrets.Pattern
	External bool
}

func dialFromPath(path string) dial {
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		d := &net.Dialer{}
		return d.DialContext(ctx, "unix", path)
	}
}
