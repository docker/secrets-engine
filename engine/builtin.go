package engine

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	"github.com/docker/secrets-engine/internal/api"
	"github.com/docker/secrets-engine/internal/logging"
	"github.com/docker/secrets-engine/internal/secrets"
	"github.com/docker/secrets-engine/plugin"
)

type internalRuntime struct {
	data   api.PluginData
	p      Plugin
	c      plugin.Config
	closed chan struct{}
	runErr func() error
	close  func() error
}

func newInternalRuntime(ctx context.Context, name string, p Plugin) (runtime, error) {
	logger, err := logging.FromContext(ctx)
	if err != nil {
		return nil, err
	}
	config := p.Config()
	if err := config.Pattern.Valid(); err != nil {
		return nil, err
	}
	data, err := api.NewPluginData(api.PluginDataUnvalidated{Name: name, Version: config.Version, Pattern: string(config.Pattern)})
	if err != nil {
		return nil, err
	}
	ctxWithCancel, cancel := context.WithCancel(ctx)
	runErr := &atomicErr{}
	closed := make(chan struct{})
	closeOnce := sync.OnceFunc(func() { close(closed) })
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Errorf("recovering from panic in %s: %s", name, debug.Stack())
				runErr.StoreFirst(fmt.Errorf("panic in %s: %v", name, r))
			}
			closeOnce()
		}()
		err := p.Run(ctxWithCancel)
		select {
		case <-ctxWithCancel.Done():
		default:
			if err == nil {
				err = fmt.Errorf("builtin plugin '%s' stopped unexpectedly", name)
			}
		}
		runErr.StoreFirst(err)
	}()
	return &internalRuntime{
		data:   data,
		p:      p,
		c:      config,
		closed: closed,
		runErr: runErr.Load,
		close: sync.OnceValue(func() error {
			cancel()
			select {
			case <-closed:
				return runErr.Load()
			case <-time.After(getPluginShutdownTimeout()):
				closeOnce()
				return fmt.Errorf("timeout waiting for plugin %s shutdown", name)
			}
		}),
	}, nil
}

type atomicErr struct {
	m   sync.Mutex
	err error
}

func (e *atomicErr) Load() error {
	e.m.Lock()
	defer e.m.Unlock()
	return e.err
}

func (e *atomicErr) StoreFirst(err error) {
	e.m.Lock()
	defer e.m.Unlock()
	if e.err != nil {
		return
	}
	e.err = err
}

func (i *internalRuntime) GetSecret(ctx context.Context, request secrets.Request) (resp secrets.Envelope, err error) {
	select {
	case <-i.closed:
		if err := i.runErr(); err != nil {
			return secrets.EnvelopeErr(request, err), err
		}
		err := fmt.Errorf("plugin %s has been shutdown", i.data.Name())
		return secrets.EnvelopeErr(request, err), err
	default:
	}
	defer func() {
		if r := recover(); r != nil {
			panicErr := fmt.Errorf("recovering from panic in plugin %s: %s", i.data.Name(), debug.Stack())
			resp = secrets.EnvelopeErr(request, panicErr)
			err = panicErr
		}
	}()
	return i.p.GetSecret(ctx, request)
}

func (i *internalRuntime) Close() error {
	return i.close()
}

func (i *internalRuntime) Data() api.PluginData {
	return i.data
}

func (i *internalRuntime) Closed() <-chan struct{} {
	return i.closed
}

func wrapBuiltins(ctx context.Context, logger logging.Logger, plugins map[string]Plugin) []launchPlan {
	var result []launchPlan
	for name, p := range plugins {
		l := func() (runtime, error) { return newInternalRuntime(ctx, name, p) }
		result = append(result, launchPlan{l, builtinPlugin, name})
		logger.Printf("discovered builtin plugin: %s", name)
	}
	return result
}
