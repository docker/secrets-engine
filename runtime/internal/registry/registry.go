package registry

import (
	"iter"

	"github.com/docker/secrets-engine/runtime/internal/plugin"
)

type RemoveFunc func()

type Registry interface {
	Register(plugin plugin.Runtime) (RemoveFunc, error)
	Iterator() iter.Seq[plugin.Runtime]
}
