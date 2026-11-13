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
// Messages travel as uncompressed binary Protobuf. The package supports
// neither streaming, nor the JSON codec, nor the gRPC and gRPC-Web protocols.
package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
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

// HTTPClient is the part of [http.Client] that a [Client] uses.
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// Client calls the procedures of one server.
type Client struct {
	httpClient   HTTPClient
	baseURL      string
	interceptors []Interceptor
}

// NewClient returns a client for the server at baseURL, for example "http://unix".
func NewClient(httpClient HTTPClient, baseURL string, opts ...ClientOption) *Client {
	var cfg config
	for _, opt := range opts {
		opt.applyToClient(&cfg)
	}
	return &Client{httpClient: httpClient, baseURL: strings.TrimRight(baseURL, "/"), interceptors: cfg.interceptors}
}

// CallUnary sends req to procedure, for example
// "/resolver.v1.ResolverService/GetSecrets", and returns the response.
// A deadline on ctx travels to the server. A call that fails returns an
// [*Error]; an interceptor may return any error.
func CallUnary[Res, Req any, PRes message[Res], PReq message[Req]](ctx context.Context, c *Client, procedure string, req *Req) (*Res, error) {
	unary := intercept(func(ctx context.Context, req proto.Message) (proto.Message, error) {
		res := PRes(new(Res))
		if err := c.call(ctx, procedure, req, res); err != nil {
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

func (c *Client) call(ctx context.Context, procedure string, req, res proto.Message) error {
	body, err := proto.Marshal(req)
	if err != nil {
		return NewError(CodeInternal, fmt.Errorf("marshal request: %w", err))
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+procedure, bytes.NewReader(body))
	if err != nil {
		return NewError(CodeUnknown, err)
	}
	httpReq.Header.Set("Content-Type", contentTypeProto)
	httpReq.Header.Set(headerProtocolVersion, protocolVersion)
	if deadline, ok := ctx.Deadline(); ok {
		if ms := time.Until(deadline).Milliseconds(); ms > 0 && ms <= maxTimeoutMs {
			httpReq.Header.Set(headerTimeout, strconv.FormatInt(ms, 10))
		}
	}
	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return asError(err, CodeUnavailable)
	}
	defer httpResp.Body.Close()
	data, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return asError(fmt.Errorf("read response: %w", err), CodeUnavailable)
	}
	contentType, _, _ := mime.ParseMediaType(httpResp.Header.Get("Content-Type"))
	if httpResp.StatusCode != http.StatusOK {
		return errorFromResponse(httpResp, contentType, data)
	}
	if contentType != contentTypeProto {
		return NewError(CodeUnknown, fmt.Errorf("invalid content-type %q: expecting %q", contentType, contentTypeProto))
	}
	if err := proto.Unmarshal(data, res); err != nil {
		return NewError(CodeInternal, fmt.Errorf("unmarshal response: %w", err))
	}
	return nil
}

func errorFromResponse(resp *http.Response, contentType string, body []byte) *Error {
	code := codeFromStatus(resp.StatusCode)
	var wire wireError
	if contentType != contentTypeJSON || json.Unmarshal(body, &wire) != nil {
		return NewError(code, errors.New(resp.Status))
	}
	if _, ok := statusByCode[wire.Code]; ok {
		code = wire.Code
	}
	return NewError(code, errors.New(wire.Message))
}
