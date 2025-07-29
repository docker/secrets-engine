package engine

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	"github.com/docker/secrets-engine/internal/logging"
	"github.com/docker/secrets-engine/internal/secrets"
	"github.com/docker/secrets-engine/plugin"
)

type internalRuntime struct {
	name   string
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
		name:   name,
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
		err := fmt.Errorf("plugin %s has been shutdown", i.name)
		return secrets.EnvelopeErr(request, err), err
	default:
	}
	defer func() {
		if r := recover(); r != nil {
			panicErr := fmt.Errorf("recovering from panic in plugin %s: %s", i.name, debug.Stack())
			resp = secrets.EnvelopeErr(request, panicErr)
			err = panicErr
		}
	}()
	return i.p.GetSecret(ctx, request)
}

func (i *internalRuntime) Close() error {
	return i.close()
}

func (i *internalRuntime) Data() pluginData {
	return pluginData{
		name:       i.name,
		pattern:    i.c.Pattern,
		version:    i.c.Version,
		pluginType: builtinPlugin,
	}
}

func (i *internalRuntime) Wait(ctx context.Context) {
	select {
	case <-i.closed:
	case <-ctx.Done():
	}
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
