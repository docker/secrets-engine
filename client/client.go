// Copyright 2025-2026 Docker, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package client

import (
	"context"
	"errors"
	"fmt"
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

	ErrSecretNotFound            = secrets.ErrNotFound
	ErrSecretsEngineNotAvailable = errors.New("secrets engine is not available")
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

// WithTimeout overrides the request timeout of the client.
//
// It is useful to set if there are hard-limits to when the client must wait
// for the server to accept the request.
//
// A timout of 0 means no request timeout will be applied.
// Negative durations are not allowed and will result in an error.
func WithTimeout(timeout time.Duration) Option {
	return func(s *config) error {
		if timeout < 0 {
			return errors.New("request timeout duration cannot be negative")
		}
		s.requestTimeout = timeout
		return nil
	}
}

// WithResponseTimeout overrides the response header timeout of the client.
//
// It is useful to set if there are long-lived user interactions required
// when the Secrets Engine requests secrets from a plugin.
//
// A responseTimeout of 0 means no response header timeout will be applied.
// Negative durations are not allowed and will result in an error.
func WithResponseTimeout(responseTimeout time.Duration) Option {
	return func(s *config) error {
		if responseTimeout < 0 {
			return errors.New("response timeout duration cannot be negative")
		}
		s.responseTimeout = responseTimeout
		return nil
	}
}

type dial func(ctx context.Context, network, addr string) (net.Conn, error)

type config struct {
	dialContext     dial
	requestTimeout  time.Duration
	responseTimeout time.Duration
}

type client struct {
	resolverClient secrets.Resolver
	listClient     resolverv1connect.ListServiceClient
}

func (c client) GetSecrets(ctx context.Context, pattern secrets.Pattern) ([]secrets.Envelope, error) {
	envelopes, err := c.resolverClient.GetSecrets(ctx, pattern)
	if isDialError(err) {
		return nil, fmt.Errorf("%w: %w", ErrSecretsEngineNotAvailable, err)
	}
	if err != nil {
		return nil, err
	}
	return envelopes, nil
}

type Client interface {
	secrets.Resolver

	ListPlugins(ctx context.Context) ([]PluginInfo, error)
}

func isDialError(err error) bool {
	if err == nil {
		return false
	}
	var oe *net.OpError
	if errors.As(err, &oe) && (oe.Op == "dial" || oe.Op == "connect") {
		return true
	}
	return false
}

func New(options ...Option) (Client, error) {
	cfg := &config{
		requestTimeout:  api.DefaultClientRequestTimeout,
		responseTimeout: api.DefaultClientResponseHeaderTimeout,
	}
	for _, opt := range options {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}
	if cfg.dialContext == nil {
		cfg.dialContext = dialFromPath(api.DaemonSocketPath())
	}
	c := &http.Client{
		Transport: &http.Transport{
			// re-use the same connection to the runtime, this speeds up subsequent
			// calls.
			MaxConnsPerHost:     api.DefaultClientMaxConnsPerHost,
			MaxIdleConnsPerHost: api.DefaultClientMaxIdleConnsPerHost,
			// keep the connection alive (good for long-lived clients)
			IdleConnTimeout: api.DefaultClientIdleConnTimeout,
			// By default it is 1 second, but can be overridden with [WithResponseTimeout]
			ResponseHeaderTimeout: cfg.responseTimeout,
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
	if isDialError(err) {
		return nil, fmt.Errorf("%w: %w", ErrSecretsEngineNotAvailable, err)
	}
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
