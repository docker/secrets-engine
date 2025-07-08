package adaptation

import (
	"errors"
	"sync"

	"github.com/sirupsen/logrus"
)

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

type Launcher func() (runtime, <-chan struct{}, error)

func register(reg registry, launch Launcher) error {
	run, closed, err := launch()
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
		if closed != nil {
			<-closed
		}
		removeFunc()
	}()
	return nil
}
