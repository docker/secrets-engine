package adaptation

import (
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/sirupsen/logrus"
)

type removeFunc func()

type registry interface {
	Register(plugin runtime) (removeFunc, error)
	GetAll() []runtime
}

type manager struct {
	m       sync.RWMutex
	plugins []runtime
}

var _ registry = &manager{}

func (m *manager) Register(plugin runtime) (removeFunc, error) {
	m.m.Lock()
	defer m.m.Unlock()
	if plugin.Data().name == "" {
		return nil, errors.New("no plugin name")
	}
	for _, p := range m.plugins {
		if p.Data().name == plugin.Data().name {
			return nil, fmt.Errorf("plugin %s already exists", plugin.Data().name)
		}
	}
	m.plugins = append(m.plugins, plugin)
	m.sort()
	return func() {
		m.remove(plugin)
	}, nil
}

func (m *manager) sort() {
	sort.Slice(m.plugins, func(i, j int) bool {
		return m.plugins[i].Data().name < m.plugins[j].Data().name
	})
	if len(m.plugins) > 0 {
		logrus.Infof("plugin priority order")
		for i, p := range m.plugins {
			logrus.Infof("  #%d: %s", i+1, p.Data().qualifiedName())
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
