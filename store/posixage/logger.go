package posixage

import "github.com/docker/secrets-engine/x/logging"

type noopLogger struct{}

func (n *noopLogger) Errorf(_ string, _ ...any) {
}

func (n *noopLogger) Printf(_ string, _ ...any) {
}

func (n *noopLogger) Warnf(_ string, _ ...any) {
}

var _ logging.Logger = &noopLogger{}
