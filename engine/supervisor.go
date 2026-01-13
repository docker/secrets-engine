package engine

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v5"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/docker/secrets-engine/engine/internal/config"
	"github.com/docker/secrets-engine/engine/internal/plugin"
	"github.com/docker/secrets-engine/engine/internal/registry"
)

type runnable func(ctx context.Context) error

type launcher func() (plugin.Runtime, error)

type launchPlan struct {
	launcher
	name string
}

// Parallelizes the launch of all managed plugins but then still waits for synchronization until
// all launch functions are at least executed once.
func syncedParallelLaunch(ctx context.Context, cfg config.Engine, reg registry.Registry, plan []launchPlan) func() {
	span := trace.SpanFromContext(ctx)
	initialProcesses := map[string]runnable{}
	upGroup := &sync.WaitGroup{}
	for _, p := range plan {
		upGroup.Add(1)
		launchedOnce := sync.OnceFunc(func() { upGroup.Done() })
		initialProcesses[p.name] = func(ctx context.Context) error {
			launcherWithOnce := launcher(func() (plugin.Runtime, error) {
				defer launchedOnce()
				return p.launcher()
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

func retryLoop(ctx context.Context, cfg config.Engine, reg registry.Registry, name string, l launcher) error {
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
