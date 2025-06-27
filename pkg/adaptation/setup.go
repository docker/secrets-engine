package adaptation

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/docker/secrets-engine/internal/ipc"
	"github.com/docker/secrets-engine/pkg/api/resolver/v1/resolverv1connect"
	"github.com/docker/secrets-engine/pkg/secrets"
)

type SetupResult struct {
	client *http.Client
	cfg    pluginCfgIn
	close  func() error
}

var _ pluginCfgInValidator = &setupValidator{}

type setupValidator struct {
	out           pluginCfgOut
	name          string
	acceptPattern func(secrets.Pattern) error
}

func Setup(conn net.Conn, v setupValidator) (*SetupResult, error) {
	chRegistrationResult := make(chan registrationResult, 1)
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	registrator := newRegistrationLogic(v, chRegistrationResult)
	httpMux.Handle(resolverv1connect.NewEngineServiceHandler(&RegisterService{registrator}))
	i, c, err := ipc.NewRuntimeIPC(conn, httpMux)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	chIpcErr := make(chan error, 1)
	go func() {
		chIpcErr <- i.Wait(ctx)
	}()
	var out pluginCfgIn
	select {
	case r := <-chRegistrationResult:
		if r.err != nil {
			i.Close()
			return nil, fmt.Errorf("failed to register plugin: %w", err)
		}
		out = r.cfg
	case err := <-chIpcErr:
		i.Close()
		return nil, fmt.Errorf("failed to register plugin, ipc error: %w", err)
	case <-time.After(getPluginRegistrationTimeout()):
		i.Close()
		return nil, errors.New("plugin registration timed out")
	}
	return &SetupResult{
		client: c,
		cfg:    out,
		close:  i.Close,
	}, nil
}

func (p setupValidator) Validate(in pluginCfgIn) (*pluginCfgOut, error) {
	if p.name != "" && in.name != p.name {
		return nil, errors.New("plugin name cannot be changed when launched by engine")
	}
	if p.name == "" && in.name == "" {
		return nil, errors.New("plugin name is required when not launched by engine")
	}
	if err := p.acceptPattern(in.pattern); err == nil {
		return nil, err
	}
	return &p.out, nil
}
