package plugin

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/docker/secrets-engine/internal/api/resolver/v1/resolverv1connect"
	"github.com/docker/secrets-engine/internal/ipc"
)

func setup(ctx context.Context, setup ipc.Setup, config cfg, onClose func(err error)) (io.Closer, error) {
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	closed := make(chan struct{})
	once := sync.OnceFunc(func() { close(closed) })
	httpMux.Handle(resolverv1connect.NewPluginServiceHandler(&pluginService{func(context.Context) {
		once()
	}}))
	setupCompleted := make(chan struct{})
	httpMux.Handle(resolverv1connect.NewResolverServiceHandler(&resolverService{config.plugin, setupCompleted, config.registrationTimeout}))
	ipc, c, err := setup(config.conn, httpMux, func(err error) {
		if errors.Is(err, io.EOF) {
			logrus.Infof("Plugin runtime stopped, plugin %s is shutting down...", config.name)
			err = nil // In the context of a plugin, the runtime shutting down IPC/plugin is not an error.
		}
		onClose(err)
	})
	if err != nil {
		return nil, err
	}
	runtimeCfg, err := doRegister(ctx, c, config.name, config.Config, config.registrationTimeout)
	if err != nil {
		ipc.Close()
		return nil, err
	}
	go func() {
		<-closed
		ipc.Close()
	}()
	logrus.Infof("Started plugin (engine: %s@%s) %s...", runtimeCfg.Engine, runtimeCfg.Version, config.name)
	close(setupCompleted)
	return ipc, nil
}
