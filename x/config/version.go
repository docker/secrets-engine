package config

import (
	"runtime/debug"
	"sync"
)

var Version = "dev"

var Commit = sync.OnceValue(func() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range bi.Settings {
			if setting.Key == "vcs.revision" {
				return setting.Value
			}
		}
	}

	return "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
})
