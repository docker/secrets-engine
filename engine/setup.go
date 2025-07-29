package engine

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/docker/secrets-engine/internal/api/resolver/v1/resolverv1connect"
	"github.com/docker/secrets-engine/internal/ipc"
	"github.com/docker/secrets-engine/internal/logging"
	"github.com/docker/secrets-engine/internal/secrets"
)

type setupResult struct {
	client *http.Client
	cfg    pluginCfgIn
	close  func() error
}

var _ pluginCfgInValidator = &runtimeCfg{}

type runtimeCfg struct {
	out  pluginCfgOut
	name string
}

func setup(logger logging.Logger, conn io.ReadWriteCloser, setup ipc.Setup, cb func(), v runtimeCfg, option ...ipc.Option) (*setupResult, error) {
	chRegistrationResult := make(chan registrationResult, 1)
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	registrator := newRegistrationLogic(v, chRegistrationResult)
	httpMux.Handle(resolverv1connect.NewEngineServiceHandler(&RegisterService{logger: logger, r: registrator}))
	chIpcErr := make(chan error, 1)
	i, c, err := setup(conn, httpMux, func(err error) {
		if errors.Is(err, io.EOF) {
			logger.Printf("Connection to plugin %v closed", v.name)
		}
		cb()
		chIpcErr <- err
	}, option...)
	if err != nil {
		return nil, err
	}
	var out pluginCfgIn
	select {
	case r := <-chRegistrationResult:
		if r.err != nil || r.cfg == nil {
			i.Close()
			return nil, fmt.Errorf("failed to register plugin: %w", r.err)
		}
		out = *r.cfg
	case err := <-chIpcErr:
		i.Close()
		return nil, fmt.Errorf("failed to register plugin, ipc error: %w", err)
	case <-time.After(getPluginRegistrationTimeout()):
		i.Close()
		return nil, errors.New("plugin registration timed out")
	}
	logger.Printf("Plugin %s@%s registered successfully with pattern %v", out.name, out.version, out.pattern)
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

func (p runtimeCfg) Validate(in pluginCfgInUnvalidated) (*pluginCfgIn, *pluginCfgOut, error) {
	pattern, err := secrets.ParsePattern(in.pattern)
	if err != nil {
		return nil, nil, err
	}
	if p.name != "" && in.name != p.name {
		return nil, nil, errors.New("plugin name cannot be changed when launched by engine")
	}
	if p.name == "" && in.name == "" {
		return nil, nil, errors.New("plugin name is required when not launched by engine")
	}
	return &pluginCfgIn{name: in.name, version: in.version, pattern: pattern.String()}, &p.out, nil
}
