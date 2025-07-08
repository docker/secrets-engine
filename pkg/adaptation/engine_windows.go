//go:build windows

package adaptation

import (
	"os"
	"strings"
)

func isExecutable(i os.FileInfo) bool {
	return strings.HasSuffix(i.Name(), ".exe")
}
