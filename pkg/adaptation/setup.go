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
	conn  net.Conn
	cfg   pluginCfgIn
	close func() error
}

func Setup(conn net.Conn, isLaunchedByEngine bool, cfg pluginCfgOut, acceptPattern func(secrets.Pattern) error) (*SetupResult, error) {
	chRegistrationResult := make(chan registrationResult, 1)
	defer close(chRegistrationResult)
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	httpMux.Handle(resolverv1connect.NewEngineServiceHandler(newRegisterService(newRegistrationLogic(&setupValidator{
		out:                cfg,
		isLaunchedByEngine: isLaunchedByEngine,
		acceptPattern:      acceptPattern,
	}, chRegistrationResult))))
	i, err := ipc.NewRuntimeIPC(conn, httpMux)
	if err != nil {
		return nil, err
	}
	i.Unblock()
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
		conn:  conn,
		cfg:   out,
		close: i.Close,
	}, nil
}

var _ pluginCfgInValidator = &setupValidator{}

type setupValidator struct {
	out                pluginCfgOut
	isLaunchedByEngine bool
	acceptPattern      func(secrets.Pattern) error
}

func (p setupValidator) Validate(in pluginCfgIn) (*pluginCfgOut, error) {
	if p.isLaunchedByEngine && in.name != "" {
		return nil, errors.New("plugin already registered with a different name")
	}
	if !p.isLaunchedByEngine && in.name == "" {
		return nil, errors.New("plugin name is empty")
	}
	if err := p.acceptPattern(in.pattern); err == nil {
		return nil, err
	}
	return &p.out, nil
}
