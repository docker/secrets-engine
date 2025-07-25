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

	"github.com/cenkalti/backoff/v5"

	"github.com/docker/secrets-engine/internal/api/resolver/v1/resolverv1connect"
	"github.com/docker/secrets-engine/internal/ipc"
	"github.com/docker/secrets-engine/internal/logging"
)

const (
	engineShutdownTimeout = 2 * time.Second
)

type engine struct {
	close func() error
}

func newEngine(ctx context.Context, cfg config) (io.Closer, error) {
	l, err := createListener(cfg.socketPath)
	if err != nil {
		return nil, err
	}

	plan := wrapBuiltins(ctx, cfg.logger, cfg.plugins)
	if !cfg.enginePluginsDisabled {
		morePlugins, err := wrapExternalPlugins(cfg)
		if err != nil {
			return nil, err
		}
		plan = append(plan, morePlugins...)
	}
	reg := &manager{}
	h := startRetryHypervisor(ctx, cfg, reg, plan)
	shutdownManagedPlugins := shutdownManagedPluginsOnce(h, reg)
	server := newServer(cfg, reg)
	done := make(chan struct{})
	var serverErr error
	go func() {
		if err := server.Serve(l); !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, io.EOF) {
			serverErr = errors.Join(serverErr, err)
		}
		serverErr = errors.Join(serverErr, shutdownManagedPlugins())
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
			stopErr := shutdownManagedPlugins()
			// Close() has its own context that's derived from the initial context passed to the engine
			ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), engineShutdownTimeout)
			defer cancel()
			return errors.Join(server.Shutdown(ctx), stopErr, serverErr)
		}),
	}, nil
}

func (e *engine) Close() error {
	return e.close()
}

func shutdownManagedPluginsOnce(stopHypervisor func(), reg registry) func() error {
	return sync.OnceValue(func() error {
		stopHypervisor()
		return parallelStop(reg.GetAll())
	})
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

func wrapExternalPlugins(cfg config) ([]launchPlan, error) {
	cfg.logger.Printf("scanning plugin dir...")
	discoveredPlugins, err := scanPluginDir(cfg.logger, cfg.pluginPath)
	if err != nil {
		return nil, err
	}
	var result []launchPlan
	for _, p := range discoveredPlugins {
		name, l := newLauncher(cfg, p)
		result = append(result, launchPlan{l, internalPlugin, name})
		cfg.logger.Printf("discovered plugin: %s", name)
	}
	return result, nil
}

func newLauncher(cfg config, pluginFile string) (string, launcher) {
	name := toDisplayName(pluginFile)
	return name, func() (runtime, error) {
		return newLaunchedPlugin(exec.Command(filepath.Join(cfg.pluginPath, pluginFile)), runtimeCfg{
			out:  pluginCfgOut{engineName: cfg.name, engineVersion: cfg.version, requestTimeout: getPluginRequestTimeout()},
			name: name,
		})
	}
}

type launcher func() (runtime, error)

func retryLoop(ctx context.Context, cfg config, reg registry, name string, l launcher) error {
	cfg.logger.Printf("registering plugin '%s'...", name)

	exponentialBackOff := backoff.NewExponentialBackOff()
	exponentialBackOff.InitialInterval = 2 * time.Second
	opts := []backoff.RetryOption{
		backoff.WithNotify(func(err error, duration time.Duration) {
			cfg.logger.Printf("retry registering plugin '%s'... (timeout: %s)", name, duration)
		}),
		backoff.WithMaxTries(cfg.maxTries),
		backoff.WithMaxElapsedTime(2 * time.Minute),
		backoff.WithBackOff(exponentialBackOff),
	}

	_, err := backoff.Retry(ctx, func() (any, error) {
		errClosed, err := register(cfg.logger, reg, l)
		if err != nil {
			cfg.logger.Errorf("registering plugin '%s': %v", name, err)
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case err := <-errClosed:
			if err != nil {
				cfg.logger.Errorf("plugin '%s' terminated: %v", name, err)
			}
			return nil, err
		}
	}, opts...)
	return err
}

func register(logger logging.Logger, reg registry, launch launcher) (<-chan error, error) {
	run, err := launch()
	if err != nil {
		return nil, err
	}
	removeFunc, err := reg.Register(run)
	if err != nil {
		// TODO: Maybe we should send the shutdown reason to the plugin before shutting down?
		if err := run.Close(); err != nil {
			logger.Errorf(err.Error())
		}
		return nil, err
	}
	errClosed := make(chan error, 1)
	go func() {
		if run.Closed() != nil {
			<-run.Closed()
		}
		removeFunc()
		errClosed <- run.Close() // close only pulls the error here but doesn't actually re-run close
	}()
	return errClosed, nil
}

func scanPluginDir(logger logging.Logger, pluginPath string) ([]string, error) {
	if pluginPath == "" {
		return nil, nil
	}

	var result []string

	entries, err := os.ReadDir(pluginPath)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Warnf("Plugin directory does not exist: %s", pluginPath)
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
		httpMux.Handle(ipc.NewHijackAcceptor(cfg.logger, func(conn net.Conn) {
			launcher := launcher(func() (runtime, error) {
				return newExternalPlugin(conn, runtimeCfg{out: pluginCfgOut{engineName: cfg.name, engineVersion: cfg.version, requestTimeout: getPluginRequestTimeout()}})
			})
			if _, err := register(cfg.logger, reg, launcher); err != nil {
				cfg.logger.Errorf("registering dynamic plugin: %v", err)
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
