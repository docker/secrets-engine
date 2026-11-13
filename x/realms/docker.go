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

package realms

import "github.com/docker/secrets-engine/secrets"

// Docker realms all start with `docker/` as the prefix.
//
// Authentication flows done by the Docker CLI, Docker Desktop and Docker related
// products must go through `docker/auth`.
//
// Docker Hub authentication (browser based OAuth login) will be prefixed
// with `docker/auth/hub/<username>`.
//
// Docker Registry authentication will be prefixed with
// `docker/auth/registry/docker/<username>`.
var (
	// Deprecated: Use [github.com/docker/secrets-engine/client/realms.DockerHubAuthentication] instead.
	DockerHubAuthentication = secrets.MustParsePattern("docker/auth/hub/**")
	// Deprecated: Use [github.com/docker/secrets-engine/client/realms.DockerHubStagingAuthentication] instead.
	DockerHubStagingAuthentication = secrets.MustParsePattern("docker/auth/hub-staging/**")
	// Deprecated: Use [github.com/docker/secrets-engine/client/realms.DockerRegistryAuthentication] instead.
	DockerRegistryAuthentication = secrets.MustParsePattern("docker/auth/registry/docker/**")
	// Deprecated: Use [github.com/docker/secrets-engine/client/realms.DockerRegistryStagingAuthentication] instead.
	DockerRegistryStagingAuthentication = secrets.MustParsePattern("docker/auth/registry/docker-staging/**")
)

var (
	// DockerHubAuthenticationMetadata holds one profile entry per signed-in
	// Docker Hub account, plus a default entry duplicating the default
	// account's profile.
	//
	// Deprecated: Use [github.com/docker/secrets-engine/client/realms.DockerHubAuthenticationMetadata] instead.
	DockerHubAuthenticationMetadata = secrets.MustParsePattern("docker/auth/metadata/hub/**")
	// DockerHubStagingAuthenticationMetadata is the staging variant of
	// [DockerHubAuthenticationMetadata].
	//
	// Deprecated: Use [github.com/docker/secrets-engine/client/realms.DockerHubStagingAuthenticationMetadata] instead.
	DockerHubStagingAuthenticationMetadata = secrets.MustParsePattern("docker/auth/metadata/hub-staging/**")
)

var (
	// DockerMCPDefault is the default realm used for MCP related secrets
	//
	// Deprecated: Use [github.com/docker/secrets-engine/client/realms.DockerMCPDefault] instead.
	DockerMCPDefault = secrets.MustParsePattern("docker/mcp/**")
	// DockerMCPOAuth is the realm used for all MCP OAuth credentials retrieved by Docker.
	//
	// Deprecated: Use [github.com/docker/secrets-engine/client/realms.DockerMCPOAuth] instead.
	DockerMCPOAuth = secrets.MustParsePattern("docker/mcp/oauth/**")
	// DockerMCPOAuthDCR is the realm used to hold Dynamic Client Registered (DCR)
	// OAuth configurations for supported MCP servers.
	//
	// Deprecated: Use [github.com/docker/secrets-engine/client/realms.DockerMCPOAuthDCR] instead.
	DockerMCPOAuthDCR = secrets.MustParsePattern("docker/mcp/oauth-dcr/**")
)

var (
	// DockerSandbox is the default realm used for Sandbox related secrets
	//
	// Deprecated: Use [github.com/docker/secrets-engine/client/realms.DockerSandbox] instead.
	DockerSandbox = secrets.MustParsePattern("docker/sandbox/**")
	// DockerSandboxOAuth is the realm used for all Sandbox OAuth credentials
	// such as third-party tokens - this does not store the Docker Auth tokens.
	//
	// Deprecated: Use [github.com/docker/secrets-engine/client/realms.DockerSandboxOAuth] instead.
	DockerSandboxOAuth = secrets.MustParsePattern("docker/sandbox/oauth/**")
)

var (
	// SecretsEngine is the default realm used for secrets-engine related secrets.
	SecretsEngine = secrets.MustParsePattern("docker/secrets-engine/**")
	// SecretsEnginePlugins is the realm used to store credentials and configuration for secrets-engine plugins.
	SecretsEnginePlugins = secrets.MustParsePattern("docker/secrets-engine/plugins/**")
)
