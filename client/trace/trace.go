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

// Package trace defines observability hooks for the secrets engine
// client SDK, in the style of net/http/httptrace.
//
// The SDK calls user-supplied functions around each public operation and
// knows nothing about any tracing or metrics library. An adapter (for example
// one built on OpenTelemetry) implements [Hooks] and returns a derived context
// from [Hooks.Start]; the SDK uses that context for the rest of the call, so
// a span started in Start becomes the parent of the underlying RPC.
//
// Install hooks with client.WithHooks, or with dockerhub.WithHooks when
// building a dockerhub.ClientAuth from your own resolver. Hooks installed on a
// client also apply to the accessor returned by its HubAuth method.
//
// Operations nest: a dockerhub operation resolves secrets through the client,
// so with hooks on both, Start for the resolver call receives the context
// returned by Start for the dockerhub call.
//
// Hooks never receive secret values, tokens, envelope contents, usernames, or
// patterns through [Operation]. The error passed to [Hooks.Done] is the error
// returned to the caller; classify it with client.ErrorKind rather than
// recording its message, which can include caller input such as a pattern.
package trace

import "context"

// Operation identifies an SDK call. All fields are low-cardinality and safe to
// use as metric or span attributes. More fields may be added later.
type Operation struct {
	// Name is one of the Op* constants.
	Name string
	// Realm is one of the Realm* constants, or empty when the operation is
	// not scoped to a realm.
	Realm string
}

// Operation names. These strings are stable: existing values will not change,
// and new operations get new names.
const (
	OpResolverGetSecrets         = "resolver.GetSecrets"
	OpAuthorizerAuthorize        = "authorizer.Authorize"
	OpVersion                    = "health.Version"
	OpPluginsList                = "plugins.ListPlugins"
	OpPluginsEnable              = "plugins.EnablePlugin"
	OpPluginsDisable             = "plugins.DisablePlugin"
	OpDockerHubListProfiles      = "dockerhub.ListProfiles"
	OpDockerHubGetDefaultProfile = "dockerhub.GetDefaultProfile"
	OpDockerHubGetDefaultSession = "dockerhub.GetDefaultSession"
	OpDockerHubGetSession        = "dockerhub.GetSession"
)

// Realm names. These strings are stable.
const (
	// RealmDockerHub is production Docker Hub.
	RealmDockerHub = "docker-hub"
	// RealmDockerHubStaging is Docker Hub staging.
	RealmDockerHubStaging = "docker-hub-staging"
)

// Hooks are called around each SDK operation. Any field may be nil. A zero
// Hooks costs a nil check per call and changes no behaviour.
//
// Hooks may be called concurrently and must be safe for concurrent use.
type Hooks struct {
	// Start is called before the operation. It may return a derived context,
	// for example one carrying a span. The SDK uses the returned context for
	// the rest of the call, including the outgoing HTTP request. Returning
	// nil keeps the original context.
	Start func(ctx context.Context, op Operation) context.Context
	// Done is called once when the operation returns, with the context
	// returned by Start and the error returned to the caller (nil on
	// success). It is not called if the operation panics.
	Done func(ctx context.Context, op Operation, err error)
}
