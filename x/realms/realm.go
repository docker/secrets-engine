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

// Package realms keeps track of known Docker realms
//
// Realms do not define a permission model and should not be used as such!
// Realms are simply contracts that clients may use to query a set of secrets.
// Once a realm has been established it MUST not change as clients would treat
// the realm as a contract.
// Clients may pin themselves to a specific realm or a group of realms.
//
// Examples:
//
//	`docker/` is a realm for all known Docker secrets.
//	`docker/auth` is a realm for all known Docker Auth secrets.
package realms

import (
	"slices"

	"github.com/docker/secrets-engine/x/secrets"
)

var (
	allAuth = []secrets.Pattern{
		DockerHubAuthentication,
		DockerHubStagingAuthentication,
		DockerRegistryAuthentication,
		DockerRegistryStagingAuthentication,
		DockerHubAuthenticationMetadata,
		DockerHubStagingAuthenticationMetadata,
	}
	allMCP = []secrets.Pattern{
		DockerMCPDefault,
		DockerMCPOAuth,
		DockerMCPOAuthDCR,
	}
	allSandbox = []secrets.Pattern{
		DockerSandbox,
		DockerSandboxOAuth,
	}
	allSecretsEngine = []secrets.Pattern{
		SecretsEngine,
		SecretsEnginePlugins,
	}

	all = slices.Concat(allAuth, allMCP, allSandbox, allSecretsEngine)
)

func All() []secrets.Pattern {
	return slices.Clone(all)
}

func AllAuth() []secrets.Pattern {
	return slices.Clone(allAuth)
}

func AllMCP() []secrets.Pattern {
	return slices.Clone(allMCP)
}

func AllSandbox() []secrets.Pattern {
	return slices.Clone(allSandbox)
}

func AllSecretsEngine() []secrets.Pattern {
	return slices.Clone(allSecretsEngine)
}
