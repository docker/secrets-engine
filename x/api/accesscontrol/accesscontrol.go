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

package accesscontrol

import (
	"context"

	"github.com/docker/secrets-engine/x/secrets"
)

type AccessControl interface {
	CheckAccess(ctx context.Context, req CheckAccessRequest) (bool, error)
}

type CheckAccessRequest struct {
	secrets.Pattern
	ProcessInfo
	SigningInfo
}

type ProcessInfo struct {
	PID                int
	Name               string
	AbsoluteBinaryPath string
}

type SigningInfoBase struct {
	SignedByDocker bool
}
