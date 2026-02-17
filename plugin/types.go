// Copyright 2025-2026 Docker, Inc.
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

package plugin

import (
	"context"
	"time"

	"github.com/docker/secrets-engine/x/api"
	"github.com/docker/secrets-engine/x/logging"
	"github.com/docker/secrets-engine/x/plugins"
	"github.com/docker/secrets-engine/x/secrets"
)

type (
	// Resolver is a type alias for secrets.Resolver, used to resolve secrets.
	Resolver = secrets.Resolver
	// Envelope is a type alias for secrets.Envelope, representing a secret envelope.
	Envelope = secrets.Envelope

	// Version is a type alias for api.Version, representing the plugin version.
	Version = api.Version
	// ID is a type alias for secrets.ID, representing a secret identifier.
	ID = secrets.ID
	// Pattern is a type alias for secrets.Pattern, used to match secret IDs.
	Pattern = secrets.Pattern
	// Logger is a type alias for logging.Logger, used for logging within plugins.
	Logger = logging.Logger
	// Plugin is an internal engine plugin.
	Plugin = plugins.Plugin
)

var ErrNotFound = secrets.ErrNotFound

type ExternalPlugin interface {
	Resolver
}

// Stub is the interface the stub provides for the plugin implementation.
type Stub interface {
	// Run starts the plugin then waits for the plugin service to exit, either due to a
	// critical error or by cancelling the context. Calling Run() while the plugin is running,
	// will result in an error. After the plugin service exits, Run() can safely be called again.
	Run(context.Context) error

	// RegistrationTimeout returns the registration timeout for the stub.
	// This is the default timeout if the plugin has not been started or
	// the timeout received in the Configure request otherwise.
	RegistrationTimeout() time.Duration

	// RequestTimeout returns the request timeout for the stub.
	// This is the default timeout if the plugin has not been started or
	// the timeout received in the Configure request otherwise.
	RequestTimeout() time.Duration
}

type Config struct {
	// Version of the plugin in semver format.
	Version Version
	// Pattern to control which IDs should match this plugin. Set to `**` to match any ID.
	Pattern Pattern
	// Logger to be used within plugin side SDK code. If nil, a default logger will be created and used.
	Logger Logger
}
