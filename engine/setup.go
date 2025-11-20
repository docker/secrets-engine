package engine

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/hashicorp/yamux"

	"github.com/docker/secrets-engine/engine/internal/config"
	"github.com/docker/secrets-engine/engine/internal/plugin"
	"github.com/docker/secrets-engine/engine/internal/routes"
	"github.com/docker/secrets-engine/x/ipc"
)

type setupResult struct {
	client *http.Client
	cfg    plugin.Metadata
	close  func() error
}

type runtimeConfig interface {
	plugin.ConfigValidator
	routes.PluginConfig
	Name() string
}

type runtimeConfigImpl struct {
	config.Debugging
	out  plugin.ConfigOut
	name string

	registrationResult chan plugin.RegistrationResult
}

func newRuntimeConfig(name string, out plugin.ConfigOut, debugging config.Debugging) runtimeConfig {
	return &runtimeConfigImpl{
		Debugging:          debugging,
		name:               name,
		out:                out,
		registrationResult: make(chan plugin.RegistrationResult, 1),
	}
}

func (p *runtimeConfigImpl) Name() string {
	return p.name
}

func (p *runtimeConfigImpl) ConfigValidator() plugin.ConfigValidator {
	return p
}

func (p *runtimeConfigImpl) RegistrationChannel() chan plugin.RegistrationResult {
	return p.registrationResult
}

func (p *runtimeConfigImpl) Validate(in plugin.Unvalidated) (plugin.Metadata, *plugin.ConfigOut, error) {
	if p.name != "" && in.Name != p.name {
		return nil, nil, errors.New("plugin name cannot be changed when launched by engine")
	}
	data, err := plugin.NewValidatedConfig(in)
	if err != nil {
		return nil, nil, err
	}
	return data, &p.out, nil
}

func setup(cfg runtimeConfig, conn io.ReadWriteCloser, cb func(), option ...ipc.Option) (*setupResult, error) {
	router := chi.NewRouter()

	if err := routes.SetupPlugins(cfg, router); err != nil {
		return nil, err
	}

	chIpcErr := make(chan error, 1)
	name := make(chan string, 1)
	i, c, err := ipc.NewServerIPC(cfg.Logger(), conn, router, func(err error) {
		if errors.Is(err, io.EOF) {
			cfg.Logger().Printf("Connection to plugin %v closed", readWithTimeout(name, cfg.Name()))
		}
		cb()
		chIpcErr <- err
	}, option...)
	if err != nil {
		return nil, err
	}
	var out plugin.Metadata
	select {
	case r := <-cfg.RegistrationChannel():
		if r.Err != nil || r.Config == nil {
			i.Close()
			return nil, fmt.Errorf("failed to register plugin: %w", r.Err)
		}
		name <- r.Config.Name().String()
		out = r.Config
	case err := <-chIpcErr:
		i.Close()
		return nil, fmt.Errorf("failed to register plugin, ipc error: %w", err)
	case <-time.After(getPluginRegistrationTimeout()):
		i.Close()
		return nil, errors.New("plugin registration timed out")
	}
	cfg.Logger().Printf("Plugin %s@%s registered successfully with pattern %v", out.Name(), out.Version(), out.Pattern())
	return &setupResult{
		client: c,
		cfg:    out,
		close: func() error {
			err := i.Close()
			// We might see this in rare circumstances when the server has sent the shutdown request to the client
			// but the client was faster in shutting down than the server completing.
			// -> it's not an error here as the intent is to shut down, and it doesn't matter who is faster
			if errors.Is(err, yamux.ErrSessionShutdown) {
				return nil
			}
			return err
		},
	}, nil
}

func readWithTimeout(ch <-chan string, fallback string) string {
	select {
	case s := <-ch:
		return s
	case <-time.After(getPluginRegistrationTimeout()):
		return fallback
	}
}
