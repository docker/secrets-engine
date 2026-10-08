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
	"io/fs"
	"net"
)

var (
	// ErrSecretsEngineNotRunning matches a [ConnectError] with [ReasonNotRunning].
	ErrSecretsEngineNotRunning = errors.New("secrets engine is not running")
	// ErrSecretsEnginePermissionDenied matches a [ConnectError] with [ReasonPermissionDenied].
	ErrSecretsEnginePermissionDenied = errors.New("permission denied connecting to the secrets engine")
	// ErrSecretsEngineTimeout matches a [ConnectError] with [ReasonTimeout].
	ErrSecretsEngineTimeout = errors.New("secrets engine did not respond in time")
)

// ConnectReason says why the client could not connect to the secrets engine.
type ConnectReason int

const (
	// ReasonUnknown is any connection failure not covered by another reason.
	ReasonUnknown ConnectReason = iota
	// ReasonNotRunning means the socket does not exist or nothing listens on it.
	ReasonNotRunning
	// ReasonPermissionDenied means the socket exists but the caller may not connect to it.
	ReasonPermissionDenied
	// ReasonTimeout means the engine did not respond before the deadline.
	ReasonTimeout
)

func (r ConnectReason) String() string {
	switch r {
	case ReasonNotRunning:
		return "not running"
	case ReasonPermissionDenied:
		return "permission denied"
	case ReasonTimeout:
		return "timeout"
	default:
		return "unknown"
	}
}

func (r ConnectReason) sentinel() error {
	switch r {
	case ReasonNotRunning:
		return ErrSecretsEngineNotRunning
	case ReasonPermissionDenied:
		return ErrSecretsEnginePermissionDenied
	case ReasonTimeout:
		return ErrSecretsEngineTimeout
	default:
		return nil
	}
}

// ConnectError means the client could not connect to the secrets engine; match a [ConnectReason] with errors.Is.
type ConnectError struct {
	Reason ConnectReason
	// SocketPath is the engine socket, empty when unknown (e.g. with [WithDialContext]).
	SocketPath string
	// Err is the underlying error.
	Err error
}

func (e *ConnectError) Error() string {
	msg := "cannot connect to the secrets engine"
	if s := e.Reason.sentinel(); s != nil {
		msg = s.Error()
	}
	if e.SocketPath != "" {
		msg += " at " + e.SocketPath
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *ConnectError) Unwrap() error { return e.Err }

// Is reports whether target is the sentinel for e.Reason.
func (e *ConnectError) Is(target error) bool {
	s := e.Reason.sentinel()
	return s != nil && target == s
}

// connectError wraps a dial error in a [ConnectError], except a cancelled context.
func connectError(socketPath string, err error) error {
	if errors.Is(err, context.Canceled) {
		return err
	}
	return &ConnectError{Reason: connectReason(err), SocketPath: socketPath, Err: err}
}

func connectReason(err error) ConnectReason {
	var ne net.Error
	switch {
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, errConnRefused):
		return ReasonNotRunning
	case errors.Is(err, fs.ErrPermission):
		return ReasonPermissionDenied
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return ReasonTimeout
	default:
		return ReasonUnknown
	}
}
