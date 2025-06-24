package plugin

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"

	resolverv1 "github.com/docker/secrets-engine/pkg/api/resolver/v1"
	"github.com/docker/secrets-engine/pkg/api/resolver/v1/resolverv1connect"
)

type registerClient struct {
	engineClient resolverv1connect.EngineServiceClient
	pluginName   string
	plugin       Plugin
	timeout      time.Duration
}

func newRegisterClient(conn net.Conn, pluginName string, plugin Plugin, timeout time.Duration) *registerClient {
	return &registerClient{
		engineClient: resolverv1connect.NewEngineServiceClient(createHTTPClient(conn), "http://unix"),
		pluginName:   pluginName,
		plugin:       plugin,
		timeout:      timeout,
	}
}

func createHTTPClient(conn net.Conn) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(context.Context, string, string) (net.Conn, error) {
				return conn, nil
			},
		},
	}
}

func (c *registerClient) register(ctx context.Context) (*RuntimeConfig, error) {
	logrus.Infof("Registering plugin %s...", c.pluginName)
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	config := c.plugin.Config()
	req := connect.NewRequest(resolverv1.RegisterPluginRequest_builder{
		Name:    proto.String(c.pluginName),
		Version: proto.String(config.Version),
		Pattern: proto.String(config.Pattern),
	}.Build())
	resp, err := c.engineClient.RegisterPlugin(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to register with secrets engine: %w", err)
	}
	return &RuntimeConfig{
		Config:  resp.Msg.GetConfig(),
		Engine:  resp.Msg.GetEngineName(),
		Version: resp.Msg.GetEngineVersion(),
	}, nil
}

func doRegister(ctx context.Context, conn net.Conn, pluginName string, plugin Plugin, timeout time.Duration) (*RuntimeConfig, error) {
	client := newRegisterClient(conn, pluginName, plugin, timeout)
	resp, err := client.register(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to register plugin %s: %w", pluginName, err)
	}
	logrus.Infof("Plugin %s registered successfully", pluginName)
	return resp, nil
}
