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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"time"

	"google.golang.org/protobuf/proto"
)

// Handler serves one procedure.
type Handler struct {
	procedure  string
	newRequest func() proto.Message
	unary      UnaryFunc
}

// NewUnaryHandler returns the handler of procedure, for example
// "/resolver.v1.ResolverService/GetSecrets". The caller sees an error that
// unary returns with its code if it is an [*Error], with CodeCanceled or
// CodeDeadlineExceeded if it is a context error, and with CodeUnknown
// otherwise.
func NewUnaryHandler[Req, Res any, PReq message[Req], PRes message[Res]](
	procedure string,
	unary func(context.Context, *Req) (*Res, error),
	opts ...HandlerOption,
) *Handler {
	var cfg config
	for _, opt := range opts {
		opt.applyToHandler(&cfg)
	}
	return &Handler{
		procedure:  procedure,
		newRequest: func() proto.Message { return PReq(new(Req)) },
		unary: intercept(func(ctx context.Context, req proto.Message) (proto.Message, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			typed, ok := req.(PReq)
			if !ok {
				return nil, NewError(CodeInternal, fmt.Errorf("unexpected request type %T", req))
			}
			res, err := unary(ctx, (*Req)(typed))
			if err != nil {
				return nil, err
			}
			if res == nil {
				return nil, NewError(CodeInternal, errors.New(procedure+" returned neither a response nor an error"))
			}
			return PRes(res), nil
		}, cfg.interceptors),
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); contentType != contentTypeProto {
		w.Header().Set("Accept-Post", contentTypeProto)
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}
	body, err := h.serve(r)
	if err != nil {
		writeError(w, err)
		return
	}
	w.Header().Set("Content-Type", contentTypeProto)
	_, _ = w.Write(body)
}

func (h *Handler) serve(r *http.Request) ([]byte, error) {
	if version := r.Header.Get(headerProtocolVersion); version != "" && version != protocolVersion {
		return nil, NewError(CodeInvalidArgument, fmt.Errorf("%s must be %q: got %q", headerProtocolVersion, protocolVersion, version))
	}
	if encoding := r.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		return nil, NewError(CodeUnimplemented, fmt.Errorf("unknown compression %q: supported encodings are identity", encoding))
	}
	ctx := r.Context()
	if timeout := r.Header.Get(headerTimeout); timeout != "" {
		ms, err := strconv.ParseUint(timeout, 10, 64)
		if err != nil || ms > maxTimeoutMs {
			return nil, NewError(CodeInvalidArgument, fmt.Errorf("invalid %s %q", headerTimeout, timeout))
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(ms)*time.Millisecond)
		defer cancel()
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, NewError(CodeUnknown, fmt.Errorf("read request: %w", err))
	}
	req := h.newRequest()
	if err := proto.Unmarshal(body, req); err != nil {
		return nil, NewError(CodeInvalidArgument, fmt.Errorf("unmarshal request: %w", err))
	}
	res, err := h.unary(ctx, req)
	if err != nil {
		return nil, err
	}
	data, err := proto.Marshal(res)
	if err != nil {
		return nil, NewError(CodeInternal, fmt.Errorf("marshal response: %w", err))
	}
	return data, nil
}

func writeError(w http.ResponseWriter, err error) {
	e := asError(err, CodeUnknown)
	wire := wireError{Code: e.code, Message: e.Message()}
	status, ok := statusByCode[wire.Code]
	if !ok {
		wire.Code, status = CodeUnknown, http.StatusInternalServerError
	}
	body, _ := json.Marshal(wire)
	w.Header().Set("Content-Type", contentTypeJSON)
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// NewServiceHandler routes the procedures of service, for example
// "resolver.v1.ResolverService", to handlers. It returns the path on which to
// mount the handler, and the handler.
func NewServiceHandler(service string, handlers ...*Handler) (string, http.Handler) {
	byProcedure := make(map[string]*Handler, len(handlers))
	for _, h := range handlers {
		byProcedure[h.procedure] = h
	}
	return "/" + service + "/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h, ok := byProcedure[r.URL.Path]; ok {
			h.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})
}
