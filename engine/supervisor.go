package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

type runnable func(ctx context.Context) error

type launchPlan struct {
	launcher
	pluginType
	name string
}

// Parallelizes the launch of all managed plugins but then still waits for synchronization until
// all launch functions are at least executed once.
func syncedParallelLaunch(ctx context.Context, cfg config, reg registry, plan []launchPlan) func() {
	initialProcesses := map[string]runnable{}
	upGroup := &sync.WaitGroup{}
	for _, p := range plan {
		upGroup.Add(1)
		launchedOnce := sync.OnceFunc(func() { upGroup.Done() })
		initialProcesses[fmt.Sprintf("[%s] %s", p.pluginType, p.name)] = func(ctx context.Context) error {
			launcherWithOnce := launcher(func() (runtime, error) {
				defer launchedOnce()
				return p.launcher()
			})
			if err := retryLoop(ctx, cfg, reg, p.name, launcherWithOnce); err != nil {
				cfg.logger.Errorf("plugin '%s' stopped: %s", p.name, err)
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
				cfg.logger.Errorf("plugin '%s' stopped: %s", name, err)
			}
		}()
	}
	upGroup.Wait()

	return sync.OnceFunc(func() {
		cancel()
		downGroup.Wait()
	})
}
