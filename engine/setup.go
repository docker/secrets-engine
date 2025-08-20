package engine

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/docker/secrets-engine/internal/api"
	"github.com/docker/secrets-engine/internal/api/resolver/v1/resolverv1connect"
	"github.com/docker/secrets-engine/internal/ipc"
	"github.com/docker/secrets-engine/internal/logging"
	"github.com/docker/secrets-engine/internal/secrets"
)

type setupResult struct {
	client *http.Client
	cfg    metadata
	close  func() error
}

var _ pluginCfgInValidator = &runtimeCfg{}

type runtimeCfg struct {
	out  pluginCfgOut
	name string
}

func setup(logger logging.Logger, conn io.ReadWriteCloser, cb func(), v runtimeCfg, option ...ipc.Option) (*setupResult, error) {
	chRegistrationResult := make(chan registrationResult, 1)
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	registrator := newRegistrationLogic(v, chRegistrationResult)
	httpMux.Handle(resolverv1connect.NewEngineServiceHandler(&RegisterService{logger: logger, r: registrator}))
	chIpcErr := make(chan error, 1)
	name := make(chan string, 1)
	i, c, err := ipc.NewServerIPC(logger, conn, httpMux, func(err error) {
		if errors.Is(err, io.EOF) {
			logger.Printf("Connection to plugin %v closed", readWithTimeout(name, v.name))
		}
		cb()
		chIpcErr <- err
	}, option...)
	if err != nil {
		return nil, err
	}
	var out metadata
	select {
	case r := <-chRegistrationResult:
		if r.err != nil || r.cfg == nil {
			i.Close()
			return nil, fmt.Errorf("failed to register plugin: %w", r.err)
		}
		name <- r.cfg.Name().String()
		out = r.cfg
	case err := <-chIpcErr:
		i.Close()
		return nil, fmt.Errorf("failed to register plugin, ipc error: %w", err)
	case <-time.After(getPluginRegistrationTimeout()):
		i.Close()
		return nil, errors.New("plugin registration timed out")
	}
	logger.Printf("Plugin %s@%s registered successfully with pattern %v", out.Name(), out.Version(), out.Pattern())
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

type pluginDataUnvalidated struct {
	Name    string
	Version string
	Pattern string
}

func (p runtimeCfg) Validate(in pluginDataUnvalidated) (metadata, *pluginCfgOut, error) {
	if p.name != "" && in.Name != p.name {
		return nil, nil, errors.New("plugin name cannot be changed when launched by engine")
	}
	data, err := newValidatedConfig(in)
	if err != nil {
		return nil, nil, err
	}
	return data, &p.out, nil
}

func newValidatedConfig(in pluginDataUnvalidated) (metadata, error) {
	name, err := api.NewName(in.Name)
	if err != nil {
		return nil, err
	}
	version, err := api.NewVersion(in.Version)
	if err != nil {
		return nil, err
	}
	pattern, err := secrets.ParsePattern(in.Pattern)
	if err != nil {
		return nil, err
	}
	return &configValidated{name: name, version: version, pattern: pattern}, nil
}

type configValidated struct {
	name    api.Name
	version api.Version
	pattern secrets.Pattern
}

func (c configValidated) Name() api.Name {
	return c.name
}

func (c configValidated) Version() api.Version {
	return c.version
}

func (c configValidated) Pattern() secrets.Pattern {
	return c.pattern
}

type metadata interface {
	Name() api.Name
	Version() api.Version
	Pattern() secrets.Pattern
}
