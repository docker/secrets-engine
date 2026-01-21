package mocks

import (
	"iter"

	"github.com/docker/secrets-engine/runtime/internal/plugin"
	"github.com/docker/secrets-engine/x/api"
	"github.com/docker/secrets-engine/x/secrets"
)

var (
	MockValidVersion = api.MustNewVersion("v7")
	MockPatternAny   = secrets.MustParsePattern("*")
)

func NewMockIterator(runtimes []plugin.Runtime) iter.Seq[plugin.Runtime] {
	return func(yield func(plugin.Runtime) bool) {
		for i := range len(runtimes) {
			if !yield(runtimes[i]) {
				return
			}
		}
	}
}
