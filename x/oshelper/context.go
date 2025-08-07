package oshelper

import (
	"context"
	"os"
	"os/signal"
)

type errCtxSignalTerminated struct {
	signal os.Signal
}

func (errCtxSignalTerminated) Error() string {
	return ""
}

func NotifyContext(ctx context.Context, signals ...os.Signal) (context.Context, context.CancelFunc) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, signals...)

	ctxCause, cancel := context.WithCancelCause(ctx)

	go func() {
		select {
		case <-ctx.Done():
			signal.Stop(ch)
			return
		case sig := <-ch:
			cancel(errCtxSignalTerminated{signal: sig})
			signal.Stop(ch)
			return
		}
	}()

	return ctxCause, func() {
		signal.Stop(ch)
		cancel(nil)
	}
}
