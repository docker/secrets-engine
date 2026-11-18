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

package rpc

import (
	"context"
	"slices"

	"google.golang.org/protobuf/proto"
)

// UnaryFunc makes or handles one call.
type UnaryFunc func(ctx context.Context, req proto.Message) (proto.Message, error)

// Interceptor wraps a call, on the client or in the handler, for example to
// reject the call or to measure it.
type Interceptor func(next UnaryFunc) UnaryFunc

type config struct {
	interceptors []Interceptor
}

// ClientOption configures a [Client].
type ClientOption interface {
	applyToClient(*config)
}

// HandlerOption configures a [Handler].
type HandlerOption interface {
	applyToHandler(*config)
}

// Option configures a [Client] or a [Handler].
type Option interface {
	ClientOption
	HandlerOption
}

// WithInterceptors wraps the calls of a client, or a handler, in
// interceptors. The first interceptor is the outermost: it sees the request
// first and the response last.
func WithInterceptors(interceptors ...Interceptor) Option {
	return interceptorsOption(interceptors)
}

type interceptorsOption []Interceptor

func (o interceptorsOption) applyToClient(c *config) {
	c.interceptors = append(c.interceptors, o...)
}

func (o interceptorsOption) applyToHandler(c *config) {
	c.interceptors = append(c.interceptors, o...)
}

func intercept(unary UnaryFunc, interceptors []Interceptor) UnaryFunc {
	for _, interceptor := range slices.Backward(interceptors) {
		unary = interceptor(unary)
	}
	return unary
}
