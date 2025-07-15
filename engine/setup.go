package engine

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/docker/secrets-engine/internal/api/resolver/v1/resolverv1connect"
	"github.com/docker/secrets-engine/internal/ipc"
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

func setup(conn io.ReadWriteCloser, cb func(), v runtimeCfg, option ...ipc.Option) (*setupResult, error) {
	chRegistrationResult := make(chan registrationResult, 1)
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	registrator := newRegistrationLogic(v, chRegistrationResult)
	httpMux.Handle(resolverv1connect.NewEngineServiceHandler(&RegisterService{registrator}))
	chIpcErr := make(chan error, 1)
	i, c, err := ipc.NewRuntimeIPC(conn, httpMux, func(err error) {
		if errors.Is(err, io.EOF) {
			logrus.Infof("Connection to plugin %v closed", v.name)
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
		if r.err != nil {
			i.Close()
			return nil, fmt.Errorf("failed to register plugin: %w", r.err)
		}
		out = r.cfg
	case err := <-chIpcErr:
		i.Close()
		return nil, fmt.Errorf("failed to register plugin, ipc error: %w", err)
	case <-time.After(getPluginRegistrationTimeout()):
		i.Close()
		return nil, errors.New("plugin registration timed out")
	}
	logrus.Infof("Plugin %s@%s registered successfully with pattern %v", out.name, out.version, out.pattern)
	return &setupResult{
		client: c,
		cfg:    out,
		close:  i.Close,
	}, nil
}

func (p runtimeCfg) Validate(in pluginCfgIn) (*pluginCfgOut, error) {
	if err := in.pattern.Valid(); err != nil {
		return nil, err
	}
	if p.name != "" && in.name != p.name {
		return nil, errors.New("plugin name cannot be changed when launched by engine")
	}
	if p.name == "" && in.name == "" {
		return nil, errors.New("plugin name is required when not launched by engine")
	}
	return &p.out, nil
}
