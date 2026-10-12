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
	"context"
	"errors"

	"connectrpc.com/connect"

	"github.com/docker/secrets-engine/client/dockerhub"
	"github.com/docker/secrets-engine/client/internal/hook"
)

// Error kinds returned by [ErrorKind]. These strings are a stable public
// contract: existing values will not change or be reused for other meanings.
// New kinds may be added; treat unknown values like [ErrorKindOther].
const (
	// ErrorKindEngineUnavailable: the secrets engine daemon could not be
	// reached ([ErrSecretsEngineNotAvailable]).
	ErrorKindEngineUnavailable = "engine_unavailable"
	// ErrorKindCanceled: the caller's context was canceled.
	ErrorKindCanceled = "canceled"
	// ErrorKindTimeout: a deadline or client timeout expired.
	ErrorKindTimeout = "timeout"
	// ErrorKindNoSession: no Docker Hub session or default profile is stored
	// ([dockerhub.ErrNoSession], [dockerhub.ErrNoDefaultProfile]).
	ErrorKindNoSession = "no_session"
	// ErrorKindAccessDenied: the engine denied access ([ErrAccessDenied]).
	ErrorKindAccessDenied = "access_denied"
	// ErrorKindNotFound: no secret matched ([ErrSecretNotFound]), or the
	// engine reported a resource as not found.
	ErrorKindNotFound = "not_found"
	// ErrorKindParse: a stored payload or daemon response could not be
	// decoded or failed validation.
	ErrorKindParse = "parse_error"
	// ErrorKindOther: any other error.
	ErrorKindOther = "other"
)

// ErrorKind classifies err into one of the ErrorKind* constants, for use as a
// low-cardinality metric or span attribute. It returns "" for a nil error.
// Wrapped and joined errors are classified by the first rule that matches, in
// the order the constants are declared.
func ErrorKind(err error) string {
	if err == nil {
		return ""
	}
	var timeout interface{ Timeout() bool }
	switch {
	case errors.Is(err, ErrSecretsEngineNotAvailable) || isDialError(err):
		return ErrorKindEngineUnavailable
	case errors.Is(err, context.Canceled) || connect.CodeOf(err) == connect.CodeCanceled:
		return ErrorKindCanceled
	case errors.Is(err, context.DeadlineExceeded) || connect.CodeOf(err) == connect.CodeDeadlineExceeded,
		errors.As(err, &timeout) && timeout.Timeout():
		return ErrorKindTimeout
	case errors.Is(err, dockerhub.ErrNoSession):
		return ErrorKindNoSession
	case errors.Is(err, ErrAccessDenied) || connect.CodeOf(err) == connect.CodePermissionDenied:
		return ErrorKindAccessDenied
	case errors.Is(err, ErrSecretNotFound) || connect.CodeOf(err) == connect.CodeNotFound:
		return ErrorKindNotFound
	}
	var malformed *hook.MalformedError
	if errors.As(err, &malformed) {
		return ErrorKindParse
	}
	return ErrorKindOther
}
