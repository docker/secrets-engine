package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/docker/secrets-engine/internal/api/resolver/v1/resolverv1connect"
	"github.com/docker/secrets-engine/internal/ipc"
)

const (
	engineShutdownTimeout = 2 * time.Second
)

type engine struct {
	close func() error
}

func newEngine(cfg config) (io.Closer, error) {
	l, err := createListener(cfg.socketPath)
	if err != nil {
		return nil, err
	}

	reg := &manager{}
	startBuiltins(context.Background(), reg, cfg.plugins)
	if !cfg.enginePluginsDisabled {
		if err := startPlugins(cfg, reg); err != nil {
			return nil, err
		}
	}
	m := sync.Mutex{}
	stopPlugins := func() error {
		m.Lock()
		defer m.Unlock()
		return parallelStop(reg.GetAll())
	}
	server := newServer(cfg, reg)
	done := make(chan struct{})
	var serverErr error
	go func() {
		if err := server.Serve(l); !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, io.EOF) {
			serverErr = errors.Join(serverErr, err)
		}
		serverErr = errors.Join(serverErr, stopPlugins())
		close(done)
	}()
	return &engine{
		close: sync.OnceValue(func() error {
			defer l.Close()
			select {
			case <-done:
				return serverErr
			default:
			}
			stopErr := stopPlugins()
			ctx, cancel := context.WithTimeout(context.Background(), engineShutdownTimeout)
			defer cancel()
			return errors.Join(server.Shutdown(ctx), stopErr, serverErr)
		}),
	}, nil
}

func (e *engine) Close() error {
	return e.close()
}

// Runs all io.Close() calls in parallel so shutdown time is T(1) and not T(n) for n plugins.
func parallelStop(plugins []runtime) error {
	errCh := make(chan error, len(plugins))
	wg := &sync.WaitGroup{}
	for _, p := range plugins {
		wg.Add(1)
		go func(pl runtime) {
			defer wg.Done()
			errCh <- pl.Close()
		}(p)
	}
	wg.Wait()
	close(errCh)
	var errs error
	for err := range errCh {
		errs = errors.Join(errs, err)
	}
	return errs
}

func startPlugins(cfg config, reg registry) error {
	logrus.Infof("starting plugins...")
	discoveredPlugins, err := discoverPlugins(cfg.pluginPath)
	if err != nil {
		return err
	}
	g := sync.WaitGroup{}
	for _, p := range discoveredPlugins {
		name, l := newLauncher(cfg, p)
		g.Add(1)
		go func() {
			logrus.Infof("starting pre-installed plugin '%s'...", name)
			if err := register(reg, l); err != nil {
				logrus.Warnf("failed to initialize pre-installed plugin '%s': %v", name, err)
			}
			g.Done()
		}()
	}
	g.Wait()
	return nil
}

func newLauncher(cfg config, pluginFile string) (string, Launcher) {
	name := toDisplayName(pluginFile)
	return name, func() (runtime, error) {
		return newLaunchedPlugin(exec.Command(filepath.Join(cfg.pluginPath, pluginFile)), runtimeCfg{
			out:  pluginCfgOut{engineName: cfg.name, engineVersion: cfg.version, requestTimeout: getPluginRequestTimeout()},
			name: name,
		})
	}
}

type Launcher func() (runtime, error)

func register(reg registry, launch Launcher) error {
	run, err := launch()
	if err != nil {
		return err
	}
	removeFunc, err := reg.Register(run)
	if err != nil {
		// TODO: Maybe we should send the shutdown reason to the plugin before shutting down?
		if err := run.Close(); err != nil {
			logrus.Error(err)
		}
		return err
	}
	go func() {
		if run.Closed() != nil {
			<-run.Closed()
		}
		removeFunc()
	}()
	return nil
}

func discoverPlugins(pluginPath string) ([]string, error) {
	if pluginPath == "" {
		return nil, nil
	}

	var result []string

	entries, err := os.ReadDir(pluginPath)
	if err != nil {
		if os.IsNotExist(err) {
			logrus.Warnf("Plugin directory does not exist: %s", pluginPath)
			return nil, nil
		}
		return nil, fmt.Errorf("failed to discover plugins in %s: %w", pluginPath, err)
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if !isExecutable(info) {
			continue
		}

		logrus.Infof("discovered plugin %s", toDisplayName(e.Name()))
		result = append(result, e.Name())
	}

	return result, nil
}

func newServer(cfg config, reg registry) *http.Server {
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	r := &resolver{reg: reg}
	httpMux.Handle(resolverv1connect.NewResolverServiceHandler(&resolverService{r}))
	if !cfg.dynamicPluginsDisabled {
		httpMux.Handle(ipc.NewHijackAcceptor(func(conn net.Conn) {
			launcher := Launcher(func() (runtime, error) {
				return newExternalPlugin(conn, runtimeCfg{out: pluginCfgOut{engineName: cfg.name, engineVersion: cfg.version, requestTimeout: getPluginRequestTimeout()}})
			})
			if err := register(reg, launcher); err != nil {
				logrus.Errorf("registering dynamic plugin: %v", err)
			}
		}))
	}
	return &http.Server{
		Handler: httpMux,
	}
}

func createListener(socketPath string) (net.Listener, error) {
	os.Remove(socketPath)
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		return nil, fmt.Errorf("failed to create socket %q: %w", socketPath, err)
	}
	l, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create socket %q: %w", socketPath, err)
	}
	return l, nil
}
