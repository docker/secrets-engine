// Copyright 2025-2026 Docker, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
