package adaptation

import (
	"sync"
	"time"
)

var (
	pluginRegistrationTimeout = DefaultPluginRegistrationTimeout
	timeoutCfgLock            sync.RWMutex
)

// SetPluginRegistrationTimeout sets the timeout for plugin registration.
func SetPluginRegistrationTimeout(t time.Duration) {
	timeoutCfgLock.Lock()
	defer timeoutCfgLock.Unlock()
	pluginRegistrationTimeout = t
}

func getPluginRegistrationTimeout() time.Duration {
	timeoutCfgLock.RLock()
	defer timeoutCfgLock.RUnlock()
	return pluginRegistrationTimeout
}
