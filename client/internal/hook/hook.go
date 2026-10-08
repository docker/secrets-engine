// Copyright 2026 Docker, Inc.
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

// Package hook holds helpers shared by the client and dockerhub packages to
// call [trace.Hooks] and to mark malformed-payload errors.
package hook

import (
	"context"

	"github.com/docker/secrets-engine/client/trace"
)

// Enabled reports whether any hook is set.
func Enabled(h trace.Hooks) bool {
	return h.Start != nil || h.Done != nil
}

func noop(error) {}

// Start calls h.Start, if set, and returns the context to use for the call
// and a function that must be called exactly once with the call's result.
// With a nil Done it returns a shared no-op and allocates nothing.
func Start(ctx context.Context, h trace.Hooks, op trace.Operation) (context.Context, func(error)) {
	if h.Start != nil {
		if derived := h.Start(ctx, op); derived != nil {
			ctx = derived
		}
	}
	if h.Done == nil {
		return ctx, noop
	}
	return ctx, func(err error) { h.Done(ctx, op, err) }
}

// MalformedError marks an error caused by a payload or response the SDK could
// not decode or validate. Its message is that of the wrapped error.
type MalformedError struct {
	Err error
}

func (e *MalformedError) Error() string { return e.Err.Error() }

func (e *MalformedError) Unwrap() error { return e.Err }

// Malformed wraps err in a [MalformedError]. It returns nil for a nil err.
func Malformed(err error) error {
	if err == nil {
		return nil
	}
	return &MalformedError{Err: err}
}
