package realms

import "github.com/docker/secrets-engine/x/secrets"

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
	DockerHubAuthentication             = secrets.MustParsePattern("docker/auth/hub/**")
	DockerHubStagingAuthentication      = secrets.MustParsePattern("docker/auth/hub-staging/**")
	DockerRegistryAuthentication        = secrets.MustParsePattern("docker/auth/registry/docker/**")
	DockerRegistryStagingAuthentication = secrets.MustParsePattern("docker/auth/registry/docker-staging/**")
)
