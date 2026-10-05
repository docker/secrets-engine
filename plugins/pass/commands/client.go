// Copyright 2026 Docker, Inc.
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

package commands

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/docker/secrets-engine/client"
	"github.com/docker/secrets-engine/x/api"
	"github.com/docker/secrets-engine/x/secrets"
)

const defaultPreflightPingTimeout = 3 * time.Second

type clientOpts struct {
	timeout         time.Duration
	responseTimeout time.Duration
	socketPath      string
}

func (o clientOpts) isUnbound() bool {
	return o.timeout == 0
}

// preflightPing fails fast when the engine is unreachable, so an unbounded
// client cannot hang resolution indefinitely.
// TODO: move into client/client.go
func preflightPing(ctx context.Context, c client.Client, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if _, err := c.Version(ctx); err != nil {
		if !errors.Is(err, client.ErrSecretsEngineNotAvailable) {
			err = fmt.Errorf("%w: %w", client.ErrSecretsEngineNotAvailable, err)
		}
		return fmt.Errorf("preflight ping: %w", err)
	}
	return nil
}

type ClientOption func(*clientOpts) error

// WithTimeout sets the client request timeout; 0 disables it.
func WithTimeout(timeout time.Duration) ClientOption {
	return func(o *clientOpts) error {
		if timeout < 0 {
			return errors.New("request timeout duration cannot be negative")
		}
		o.timeout = timeout
		return nil
	}
}

// WithResponseTimeout sets the client response header timeout; 0 disables it.
func WithResponseTimeout(responseTimeout time.Duration) ClientOption {
	return func(o *clientOpts) error {
		if responseTimeout < 0 {
			return errors.New("response timeout duration cannot be negative")
		}
		o.responseTimeout = responseTimeout
		return nil
	}
}

// WithSocketPath overrides the default [api.DesktopSocketPath].
func WithSocketPath(socketPath string) ClientOption {
	return func(o *clientOpts) error {
		if socketPath == "" {
			return errors.New("no path provided")
		}
		o.socketPath = socketPath
		return nil
	}
}

func parseClientOptions(options ...ClientOption) (clientOpts, error) {
	opts := clientOpts{
		timeout:         api.DefaultClientRequestTimeout,
		responseTimeout: api.DefaultClientResponseHeaderTimeout,
	}
	for _, o := range options {
		if err := o(&opts); err != nil {
			return clientOpts{}, err
		}
	}
	return opts, nil
}

func newClient(opts clientOpts) (client.Client, error) {
	socketPath := opts.socketPath
	if socketPath == "" {
		socketPath = api.DesktopSocketPath()
	}
	c, err := client.New(client.WithSocketPath(socketPath),
		client.WithTimeout(opts.timeout),
		client.WithResponseTimeout(opts.responseTimeout),
	)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func authorize(ctx context.Context, a secrets.Authorizer, patterns ...secrets.Pattern) error {
	resp, err := a.Authorize(ctx, patterns...)
	if err != nil {
		return fmt.Errorf("authorizing: %w", err)
	}
	if !resp.Allow {
		return fmt.Errorf("authorizing: %w", secrets.ErrAccessDenied)
	}
	return nil
}
