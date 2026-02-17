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

package plugin

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	resolverv1 "github.com/docker/secrets-engine/x/api/resolver/v1"
	"github.com/docker/secrets-engine/x/api/resolver/v1/resolverv1connect"
)

type registerClient struct {
	engineClient resolverv1connect.RegisterServiceClient
	pluginName   string
	config       Config
	timeout      time.Duration
}

func newRegisterClient(c *http.Client, pluginName string, config Config, timeout time.Duration) *registerClient {
	return &registerClient{
		engineClient: resolverv1connect.NewRegisterServiceClient(c, "http://unix"),
		pluginName:   pluginName,
		config:       config,
		timeout:      timeout,
	}
}

func (c *registerClient) register(ctx context.Context) (*runtimeConfig, error) {
	c.config.Logger.Printf("Registering plugin %s...", c.pluginName)
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req := connect.NewRequest(resolverv1.RegisterPluginRequest_builder{
		Name:    proto.String(c.pluginName),
		Version: proto.String(c.config.Version.String()),
		Pattern: proto.String(c.config.Pattern.String()),
	}.Build())
	resp, err := c.engineClient.RegisterPlugin(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to register with secrets engine: %w", err)
	}
	return &runtimeConfig{
		Engine:  resp.Msg.GetEngineName(),
		Version: resp.Msg.GetEngineVersion(),
	}, nil
}

type runtimeConfig struct {
	Engine  string
	Version string
}

func doRegister(ctx context.Context, c *http.Client, pluginName string, config Config, timeout time.Duration) (*runtimeConfig, error) {
	client := newRegisterClient(c, pluginName, config, timeout)
	resp, err := client.register(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to register plugin %s: %w", pluginName, err)
	}
	config.Logger.Printf("Plugin %s registered successfully", pluginName)
	return resp, nil
}
