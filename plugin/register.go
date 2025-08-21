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
	engineClient resolverv1connect.EngineServiceClient
	pluginName   string
	config       Config
	timeout      time.Duration
}

func newRegisterClient(c *http.Client, pluginName string, config Config, timeout time.Duration) *registerClient {
	return &registerClient{
		engineClient: resolverv1connect.NewEngineServiceClient(c, "http://unix"),
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
