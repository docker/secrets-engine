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

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strconv"
	"time"

	"google.golang.org/protobuf/proto"
)

const (
	getSecretsProcedure    = "/resolver.v1.ResolverService/GetSecrets"
	authorizeProcedure     = "/resolver.v1.AuthorizerService/Authorize"
	getVersionProcedure    = "/health.v1.VersionService/GetVersion"
	listPluginsProcedure   = "/plugins.v1.PluginManagementService/ListPlugins"
	enablePluginProcedure  = "/plugins.v1.PluginManagementService/EnablePlugin"
	disablePluginProcedure = "/plugins.v1.PluginManagementService/DisablePlugin"
)

const (
	baseURL          = "http://unix"
	contentTypeProto = "application/proto"
	contentTypeJSON  = "application/json"
	maxTimeoutMs     = 9_999_999_999
)

// call sends a unary request in the Connect protocol:
// https://connectrpc.com/docs/protocol#unary-request
func (c client) call(ctx context.Context, procedure string, req, resp proto.Message) error {
	body, err := proto.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+procedure, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", contentTypeProto)
	httpReq.Header.Set("Connect-Protocol-Version", "1")
	if deadline, ok := ctx.Deadline(); ok {
		if ms := time.Until(deadline).Milliseconds(); ms > 0 && ms <= maxTimeoutMs {
			httpReq.Header.Set("Connect-Timeout-Ms", strconv.FormatInt(ms, 10))
		}
	}
	httpResp, err := c.httpClient.Do(httpReq)
	if opErr, ok := errors.AsType[*net.OpError](err); ok && isDialError(opErr) {
		return c.connectError(opErr)
	}
	if err != nil {
		return err
	}
	defer httpResp.Body.Close()
	data, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	contentType, _, _ := mime.ParseMediaType(httpResp.Header.Get("Content-Type"))
	if httpResp.StatusCode != http.StatusOK {
		return newRPCError(httpResp, contentType, data)
	}
	if contentType != contentTypeProto {
		return fmt.Errorf("invalid content-type %q: expecting %q", contentType, contentTypeProto)
	}
	if err := proto.Unmarshal(data, resp); err != nil {
		return fmt.Errorf("unmarshal response: %w", err)
	}
	return nil
}

func newRPCError(resp *http.Response, contentType string, body []byte) *RPCError {
	rpcErr := &RPCError{Code: codeFromStatus(resp.StatusCode), Message: resp.Status}
	if contentType != contentTypeJSON {
		return rpcErr
	}
	var wire struct {
		Code    Code   `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		return rpcErr
	}
	if wire.Code != "" {
		rpcErr.Code = wire.Code
	}
	rpcErr.Message = wire.Message
	return rpcErr
}

func codeFromStatus(status int) Code {
	switch status {
	case http.StatusBadRequest:
		return CodeInternal
	case http.StatusUnauthorized:
		return CodeUnauthenticated
	case http.StatusForbidden:
		return CodePermissionDenied
	case http.StatusNotFound:
		return CodeUnimplemented
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return CodeUnavailable
	default:
		return CodeUnknown
	}
}
