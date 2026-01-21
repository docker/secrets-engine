package runtime

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v5"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/docker/secrets-engine/runtime/internal/config"
	"github.com/docker/secrets-engine/runtime/internal/plugin"
	"github.com/docker/secrets-engine/runtime/internal/registry"
)

type runnable func(ctx context.Context) error

type starter func() (plugin.Runtime, error)

type launchPlan struct {
	starter
	pluginType
	name string
}

type pluginType string

const (
	internalPlugin pluginType = "internal" // launched by the engine
	externalPlugin pluginType = "external" // launched externally
	builtinPlugin  pluginType = "builtin"  // no binary only Go interface
)

// Parallelizes the launch of all managed plugins but then still waits for synchronization until
// all launch functions are at least executed once.
func syncedParallelLaunch(ctx context.Context, cfg config.Engine, reg registry.Registry, plan []launchPlan) func() {
	span := trace.SpanFromContext(ctx)
	initialProcesses := map[string]runnable{}
	upGroup := &sync.WaitGroup{}
	for _, p := range plan {
		upGroup.Add(1)
		launchedOnce := sync.OnceFunc(func() { upGroup.Done() })
		initialProcesses[fmt.Sprintf("[%s] %s", p.pluginType, p.name)] = func(ctx context.Context) error {
			launcherWithOnce := starter(func() (plugin.Runtime, error) {
				defer launchedOnce()
				return p.starter()
			})
			if err := retryLoop(ctx, cfg, reg, p.name, launcherWithOnce); err != nil && !errors.Is(err, context.Canceled) {
				cfg.Logger().Errorf("plugin '%s' stopped: %s", p.name, err)
				return err
			}
			return nil
		}
	}

	ctxChild, cancel := context.WithCancel(context.WithoutCancel(ctx))
	downGroup := &sync.WaitGroup{}

	for name, run := range initialProcesses {
		downGroup.Add(1)

		go func() {
			defer downGroup.Done()
			err := run(ctxChild)
			if err != nil && !errors.Is(err, context.Canceled) {
				span.RecordError(err, trace.WithAttributes(attribute.String("phase", "retry_ended")))
				cfg.Logger().Errorf("plugin '%s' stopped: %s", name, err)
			}
		}()
	}
	upGroup.Wait()

	return sync.OnceFunc(func() {
		cancel()
		downGroup.Wait()
	})
}

func retryLoop(ctx context.Context, cfg config.Engine, reg registry.Registry, name string, l starter) error {
	cfg.Logger().Printf("registering plugin '%s'...", name)

	exponentialBackOff := backoff.NewExponentialBackOff()
	exponentialBackOff.InitialInterval = 2 * time.Second
	opts := []backoff.RetryOption{
		backoff.WithNotify(func(err error, duration time.Duration) {
			cfg.Logger().Printf("retry registering plugin '%s' (timeout: %s): %s", name, duration, err)
		}),
		backoff.WithMaxTries(cfg.PluginLaunchMaxRetries()),
		backoff.WithMaxElapsedTime(2 * time.Minute),
		backoff.WithBackOff(exponentialBackOff),
	}

	_, err := backoff.Retry(ctx, func() (any, error) {
		errClosed, err := register(ctx, reg, l)
		if err != nil {
			cfg.Logger().Errorf("registering plugin '%s': %v", name, err)
			return nil, err
		}
		exponentialBackOff.Reset()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case err := <-errClosed:
			if err != nil {
				cfg.Logger().Errorf("plugin '%s' terminated: %v", name, err)
			}
			return nil, err
		}
	}, opts...)
	return err
}
