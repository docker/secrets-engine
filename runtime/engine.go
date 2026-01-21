package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/docker/secrets-engine/runtime/internal/config"
	"github.com/docker/secrets-engine/runtime/internal/plugin"
	"github.com/docker/secrets-engine/runtime/internal/registry"
	"github.com/docker/secrets-engine/runtime/internal/routes"
	"github.com/docker/secrets-engine/runtime/internal/runtime"
	"github.com/docker/secrets-engine/runtime/internal/runtime/builtin"
	"github.com/docker/secrets-engine/x/ipc"
	"github.com/docker/secrets-engine/x/logging"
)

const (
	engineShutdownTimeout                   = 2 * time.Second
	engineServerDefaultRequestHeaderTimeout = 2 * time.Second
)

type engine interface {
	io.Closer
	Plugins() []string
}

type engineImpl struct {
	reg   registry.Registry
	close func() error
}

func newEngine(ctx context.Context, cfg config.Engine) (engine, error) {
	plan := wrapBuiltins(ctx, cfg, runtime.GetPluginShutdownTimeout())
	if cfg.LaunchedPluginsEnabled() {
		morePlugins, err := wrapExternalPlugins(cfg)
		if err != nil {
			return nil, err
		}
		plan = append(plan, morePlugins...)
	}
	reg := registry.NewManager(cfg.Logger())
	h := syncedParallelLaunch(ctx, cfg, reg, plan)
	shutdownManagedPlugins := shutdownManagedPluginsOnce(h, reg)

	server, err := newServer(cfg, reg)
	if err != nil {
		return nil, err
	}

	done := make(chan struct{})
	var serverErr error
	go func() {
		defer func() { _ = shutdownManagedPlugins() }()
		if err := server.Serve(cfg.Listener()); !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, io.EOF) {
			serverErr = errors.Join(serverErr, err)
		}
		close(done)
	}()
	return &engineImpl{
		reg: reg,
		close: sync.OnceValue(func() error {
			defer cfg.Listener().Close()
			stopErr := shutdownManagedPlugins()
			// Close() has its own context that's derived from the initial context passed to the runtime
			ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), engineShutdownTimeout)
			defer cancel()
			shutdownErr := server.Shutdown(ctx)
			<-done // it's safe to wait here (never blocks) as we just have shut down the server
			return errors.Join(shutdownErr, stopErr, serverErr)
		}),
	}, nil
}

func (e *engineImpl) Close() error {
	return e.close()
}

func (e *engineImpl) Plugins() []string {
	var plugins []string
	for plugin := range e.reg.Iterator() {
		plugins = append(plugins, plugin.Name().String())
	}
	return plugins
}

func wrapBuiltins(ctx context.Context, cfg config.Engine, shutdownTimeout time.Duration) []launchPlan {
	var result []launchPlan
	for c, p := range cfg.Plugins() {
		l := func() (plugin.Runtime, error) { return builtin.NewInternalRuntime(ctx, p, c, shutdownTimeout) }
		result = append(result, launchPlan{l, builtinPlugin, c.Name().String()})
		cfg.Logger().Printf("discovered builtin plugin: %s", c.Name())
	}
	return result
}

func shutdownManagedPluginsOnce(stopSupervisor func(), reg registry.Registry) func() error {
	return sync.OnceValue(func() error {
		stopSupervisor()
		return parallelStop(reg.Iterator())
	})
}

// Runs all io.Close() calls in parallel so shutdown time is T(1) and not T(n) for n plugins.
func parallelStop(it iter.Seq[plugin.Runtime]) error {
	var errList []error
	m := sync.Mutex{}
	wg := &sync.WaitGroup{}
	for p := range it {
		wg.Add(1)
		go func(pl plugin.Runtime) {
			defer wg.Done()
			err := pl.Close()

			m.Lock()
			defer m.Unlock()
			errList = append(errList, err)
		}(p)
	}
	wg.Wait()
	return errors.Join(errList...)
}

func wrapExternalPlugins(cfg config.Engine) ([]launchPlan, error) {
	cfg.Logger().Printf("scanning plugin dir...")
	discoveredPlugins, err := scanPluginDir(cfg)
	if err != nil {
		return nil, err
	}
	var result []launchPlan
	for _, p := range discoveredPlugins {
		name, l := runtime.NewLauncher(cfg, p)
		result = append(result, launchPlan{l, internalPlugin, name})
		cfg.Logger().Printf("discovered plugin: %s", name)
	}
	return result, nil
}

func register(ctx context.Context, reg registry.Registry, launch launcher) (<-chan error, error) {
	logger, err := logging.FromContext(ctx)
	if err != nil {
		return nil, err
	}
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
			select {
			case <-run.Closed():
			case <-ctx.Done():
			}
		}
		removeFunc()
		errClosed <- run.Close() // close only pulls the error here but doesn't actually re-run close
	}()
	return errClosed, nil
}

func scanPluginDir(cfg config.Engine) ([]string, error) {
	if cfg.PluginPath() == "" {
		return nil, nil
	}

	var result []string

	entries, err := os.ReadDir(cfg.PluginPath())
	if err != nil {
		if os.IsNotExist(err) {
			cfg.Logger().Warnf("Plugin directory does not exist: %s", cfg.PluginPath())
			return nil, nil
		}
		return nil, fmt.Errorf("failed to discover plugins in %s: %w", cfg.PluginPath(), err)
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

func newServer(cfg config.Engine, reg registry.Registry) (*http.Server, error) {
	router := chi.NewRouter()

	if err := routes.Setup(cfg, reg, router); err != nil {
		return nil, err
	}

	if cfg.DynamicPluginsEnabled() {
		router.Handle(ipc.NewHijackAcceptor(cfg.Logger(), func(ctx context.Context, conn io.ReadWriteCloser) {
			span := trace.SpanFromContext(ctx)
			launcher := launcher(func() (plugin.Runtime, error) {
				return runtime.NewExternalPlugin(
					runtime.NewRuntimeConfig(
						"", // TODO:(@benehiko) might need a name here? original code omitted it
						plugin.ConfigOut{
							EngineName:     cfg.Name(),
							EngineVersion:  cfg.Version(),
							RequestTimeout: runtime.GetPluginRequestTimeout(),
						},
						cfg,
					),
					conn,
				)
			})
			errDone, err := register(logging.WithLogger(ctx, cfg.Logger()), reg, launcher)
			if err != nil {
				cfg.Logger().Errorf("registering dynamic plugin: %v", err)
			}
			select {
			case <-ctx.Done():
			case err := <-errDone:
				if err != nil && !errors.Is(err, context.Canceled) {
					span.RecordError(err, trace.WithAttributes(attribute.String("phase", "external_plugin_disconnected")))
					cfg.Logger().Errorf("external plugin '%s' stopped: %v", cfg.Name(), err)
				}
			}
		}))
	}
	return &http.Server{
		// We are setting no timeouts on the server itself.
		// A middleware will set the request timeout for us.
		// This gives us more granular control over what requires a short
		// timeout vs what should be kept alive for a long time.
		// e.g. request secret might prompt the user for input, the input
		// could take more than 1 minute, we should keep the request alive for
		// that duration minimum.
		ReadTimeout:  0,
		WriteTimeout: 0,
		// The header should be relatively quick to read. Let's set a limit on
		// that so that any connection drops will cancel the request.
		ReadHeaderTimeout: engineServerDefaultRequestHeaderTimeout,
		Handler:           router,
	}, nil
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
