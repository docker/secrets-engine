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
	"errors"
	"io"
	"net/http"
	"sync"

	resolverv1 "github.com/docker/secrets-engine/x/api/resolver"
	"github.com/docker/secrets-engine/x/api/resolver/v1/resolverv1connect"
	"github.com/docker/secrets-engine/x/ipc"
)

func setup(ctx context.Context, config cfg, onClose func(err error)) (io.Closer, error) {
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
	httpMux.Handle(resolverv1connect.NewResolverServiceHandler(&resolverService{
		handler:             resolverv1.NewResolverHandler(config.plugin),
		setupCompleted:      setupCompleted,
		registrationTimeout: config.registrationTimeout,
	}))
	ipc, c, err := ipc.NewClientIPC(config.Logger, config.conn, httpMux, func(err error) {
		if errors.Is(err, io.EOF) {
			config.Logger.Printf("Plugin runtime stopped, plugin %s is shutting down...", config.name)
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
	config.Logger.Printf("Started plugin (runtime: %s@%s) %s...", runtimeCfg.Engine, runtimeCfg.Version, config.name)
	close(setupCompleted)
	return ipc, nil
}
