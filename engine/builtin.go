package engine

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	"github.com/docker/secrets-engine/x/logging"
	"github.com/docker/secrets-engine/x/secrets"
)

type internalRuntime struct {
	metadata
	p      Plugin
	closed chan struct{}
	runErr func() error
	close  func() error
}

func newInternalRuntime(ctx context.Context, p Plugin, c metadata) (runtime, error) {
	logger, err := logging.FromContext(ctx)
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
				logger.Errorf("recovering from panic in %s: %s", c.Name(), debug.Stack())
				runErr.StoreFirst(fmt.Errorf("panic in %s: %v", c.Name(), r))
			}
			closeOnce()
		}()
		err := p.Run(ctxWithCancel)
		select {
		case <-ctxWithCancel.Done():
		default:
			if err == nil {
				err = fmt.Errorf("builtin plugin '%s' stopped unexpectedly", c.Name())
			}
		}
		runErr.StoreFirst(err)
	}()
	return &internalRuntime{
		metadata: c,
		p:        p,
		closed:   closed,
		runErr:   runErr.Load,
		close: sync.OnceValue(func() error {
			cancel()
			select {
			case <-closed:
				return runErr.Load()
			case <-time.After(getPluginShutdownTimeout()):
				closeOnce()
				return fmt.Errorf("timeout waiting for plugin %s shutdown", c.Name())
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

func (i *internalRuntime) GetSecrets(ctx context.Context, request secrets.Request) (resp []secrets.Envelope, err error) {
	select {
	case <-i.closed:
		if err := i.runErr(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("plugin %s has been shutdown", i.Name())
	default:
	}
	defer func() {
		if r := recover(); r != nil {
			panicErr := fmt.Errorf("recovering from panic in plugin %s: %s", i.Name(), debug.Stack())
			resp = nil
			err = panicErr
		}
	}()
	return i.p.GetSecrets(ctx, request)
}

func (i *internalRuntime) Close() error {
	return i.close()
}

func (i *internalRuntime) Closed() <-chan struct{} {
	return i.closed
}

func wrapBuiltins(ctx context.Context, logger logging.Logger, plugins map[metadata]Plugin) []launchPlan {
	var result []launchPlan
	for c, p := range plugins {
		l := func() (runtime, error) { return newInternalRuntime(ctx, p, c) }
		result = append(result, launchPlan{l, builtinPlugin, c.Name().String()})
		logger.Printf("discovered builtin plugin: %s", c.Name())
	}
	return result
}
