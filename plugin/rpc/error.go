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
	"errors"
	"net/http"
	"os"

	clientrpc "github.com/docker/secrets-engine/client/rpc"
)

type Code = clientrpc.Code

const (
	CodeCanceled           = clientrpc.CodeCanceled
	CodeUnknown            = clientrpc.CodeUnknown
	CodeInvalidArgument    = clientrpc.CodeInvalidArgument
	CodeDeadlineExceeded   = clientrpc.CodeDeadlineExceeded
	CodeNotFound           = clientrpc.CodeNotFound
	CodeAlreadyExists      = clientrpc.CodeAlreadyExists
	CodePermissionDenied   = clientrpc.CodePermissionDenied
	CodeResourceExhausted  = clientrpc.CodeResourceExhausted
	CodeFailedPrecondition = clientrpc.CodeFailedPrecondition
	CodeAborted            = clientrpc.CodeAborted
	CodeOutOfRange         = clientrpc.CodeOutOfRange
	CodeUnimplemented      = clientrpc.CodeUnimplemented
	CodeInternal           = clientrpc.CodeInternal
	CodeUnavailable        = clientrpc.CodeUnavailable
	CodeDataLoss           = clientrpc.CodeDataLoss
	CodeUnauthenticated    = clientrpc.CodeUnauthenticated
)

type Error = clientrpc.Error

func NewError(code Code, err error) *Error {
	return clientrpc.NewError(code, err)
}

func CodeOf(err error) Code {
	return clientrpc.CodeOf(err)
}

type wireError struct {
	Code    Code   `json:"code"`
	Message string `json:"message,omitempty"`
}

// https://connectrpc.com/docs/protocol#error-codes
var statusByCode = map[Code]int{
	CodeCanceled:           499,
	CodeUnknown:            http.StatusInternalServerError,
	CodeInvalidArgument:    http.StatusBadRequest,
	CodeDeadlineExceeded:   http.StatusGatewayTimeout,
	CodeNotFound:           http.StatusNotFound,
	CodeAlreadyExists:      http.StatusConflict,
	CodePermissionDenied:   http.StatusForbidden,
	CodeResourceExhausted:  http.StatusTooManyRequests,
	CodeFailedPrecondition: http.StatusBadRequest,
	CodeAborted:            http.StatusConflict,
	CodeOutOfRange:         http.StatusBadRequest,
	CodeUnimplemented:      http.StatusNotImplemented,
	CodeInternal:           http.StatusInternalServerError,
	CodeUnavailable:        http.StatusServiceUnavailable,
	CodeDataLoss:           http.StatusInternalServerError,
	CodeUnauthenticated:    http.StatusUnauthorized,
}

func asError(err error) *Error {
	if e, ok := errors.AsType[*Error](err); ok {
		return e
	}
	switch {
	case errors.Is(err, context.Canceled):
		return NewError(CodeCanceled, err)
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return NewError(CodeDeadlineExceeded, err)
	default:
		return NewError(CodeUnknown, err)
	}
}
