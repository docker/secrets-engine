package engine

import (
	"fmt"
	"iter"
	"slices"
	"strings"
	"sync"

	"github.com/docker/secrets-engine/x/logging"
)

type removeFunc func()

type registry interface {
	Register(plugin runtime) (removeFunc, error)
	Iterator() iter.Seq[runtime]
}

type manager struct {
	m        sync.RWMutex
	plugins  []runtime
	visitors map[*visitor]struct{}
	logger   logging.Logger
}

func newManager(l logging.Logger) *manager {
	return &manager{logger: l, visitors: map[*visitor]struct{}{}}
}

type visitor struct {
	index int
}

var _ registry = &manager{}

func (m *manager) Register(plugin runtime) (removeFunc, error) {
	m.m.Lock()
	defer m.m.Unlock()
	for _, p := range m.plugins {
		if p.Name().String() == plugin.Name().String() {
			return nil, fmt.Errorf("plugin %s already exists", plugin.Name())
		}
	}
	m.plugins = append(m.plugins, plugin)
	m.sort()
	return func() {
		m.remove(plugin)
	}, nil
}

func (m *manager) sort() {
	slices.SortFunc(m.plugins, func(a, b runtime) int {
		return strings.Compare(a.Name().String(), b.Name().String())
	})
	if len(m.plugins) > 0 {
		m.logger.Printf("plugin priority order")
		for i, p := range m.plugins {
			m.logger.Printf("  #%d: %s", i+1, p.Name())
		}
	}
}

func (m *manager) Iterator() iter.Seq[runtime] {
	m.m.Lock()
	defer m.m.Unlock()
	startIdx := -1
	if len(m.plugins) > 0 {
		startIdx = 0
	}
	v := &visitor{index: startIdx}
	m.visitors[v] = struct{}{}

	return func(yield func(runtime) bool) {
		defer m.removeVisitor(v)

		for {
			p, ok := m.visit(v)
			if !ok {
				return
			}
			if !yield(p) {
				return
			}
		}
	}
}

func (m *manager) removeVisitor(v *visitor) {
	m.m.Lock()
	defer m.m.Unlock()
	delete(m.visitors, v)
}

func (m *manager) visit(v *visitor) (runtime, bool) {
	m.m.RLock()
	defer m.m.RUnlock()

	if _, ok := m.visitors[v]; !ok {
		return nil, false
	}

	if v.index < 0 || v.index >= len(m.plugins) {
		return nil, false
	}

	idx := v.index
	p := m.plugins[idx]

	if v.index+1 < len(m.plugins) {
		v.index++
	} else {
		v.index = -1
	}

	return p, true
}

func (m *manager) remove(plugin runtime) {
	m.m.Lock()
	defer m.m.Unlock()
	idx := -1
	for i, p := range m.plugins {
		if p == plugin {
			m.plugins = append(m.plugins[:i], m.plugins[i+1:]...)
			idx = i
			break
		}
	}
	for it := range m.visitors {
		if it.index >= idx {
			it.index--
		}
	}
}
