//go:build windows

package engine

import (
	"os"
	"strings"
)

func isExecutable(i os.FileInfo) bool {
	return strings.HasSuffix(i.Name(), ".exe")
}
