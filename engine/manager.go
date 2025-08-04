package engine

import (
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/docker/secrets-engine/internal/logging"
)

type removeFunc func()

type registry interface {
	Register(plugin runtime) (removeFunc, error)
	GetAll() []runtime
}

type manager struct {
	m       sync.RWMutex
	plugins []runtime
	logger  logging.Logger
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

func (m *manager) GetAll() []runtime {
	m.m.RLock()
	defer m.m.RUnlock()
	return m.plugins
}

func (m *manager) remove(plugin runtime) {
	m.m.Lock()
	defer m.m.Unlock()
	for i, p := range m.plugins {
		if p == plugin {
			m.plugins = append(m.plugins[:i], m.plugins[i+1:]...)
		}
	}
}
