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
