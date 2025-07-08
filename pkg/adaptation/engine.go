package adaptation

import (
	"errors"
	"fmt"
	"os"
	"strings"
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

func toDisplayName(filename string) string {
	return strings.TrimSuffix(filename, ".exe")
}
