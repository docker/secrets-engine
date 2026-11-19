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

// Package rpc implements unary calls in the Connect protocol on net/http:
// https://connectrpc.com/docs/protocol
//
// Messages travel as uncompressed binary Protobuf; a handler also accepts
// JSON. The package supports neither streaming, nor the gRPC and gRPC-Web
// protocols.
package rpc

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/proto"

	clientrpc "github.com/docker/secrets-engine/client/rpc"
)

const (
	contentTypeProto = "application/proto"
	contentTypeJSON  = "application/json"

	headerProtocolVersion = "Connect-Protocol-Version"
	headerTimeout         = "Connect-Timeout-Ms"

	protocolVersion = "1"
	maxTimeoutMs    = 9_999_999_999
)

type message[T any] interface {
	*T
	proto.Message
}

type HTTPClient = clientrpc.HTTPClient

// Client calls the procedures of one server.
type Client struct {
	client       *clientrpc.Client
	interceptors []Interceptor
}

// NewClient returns a client for the server at baseURL, for example "http://unix".
func NewClient(httpClient HTTPClient, baseURL string, opts ...ClientOption) *Client {
	var cfg config
	for _, opt := range opts {
		opt.applyToClient(&cfg)
	}
	return &Client{client: clientrpc.NewClient(httpClient, baseURL), interceptors: cfg.interceptors}
}

// CallUnary sends req to procedure, for example
// "/resolver.v1.ResolverService/GetSecrets", and returns the response.
// A deadline on ctx travels to the server. A call that fails returns an
// [*Error]; an interceptor may return any error.
func CallUnary[Res, Req any, PRes message[Res], PReq message[Req]](ctx context.Context, c *Client, procedure string, req *Req) (*Res, error) {
	unary := intercept(func(ctx context.Context, req proto.Message) (proto.Message, error) {
		res := PRes(new(Res))
		if err := c.client.Call(ctx, procedure, req, res); err != nil {
			return nil, err
		}
		return res, nil
	}, c.interceptors)
	res, err := unary(ctx, PReq(req))
	if err != nil {
		return nil, err
	}
	typed, ok := res.(PRes)
	if !ok {
		return nil, NewError(CodeInternal, fmt.Errorf("unexpected response type %T", res))
	}
	return (*Res)(typed), nil
}
