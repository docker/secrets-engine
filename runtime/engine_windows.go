//go:build windows

package runtime

import (
	"os"
	"strings"
)

const suffix = ".exe"

func isExecutable(i os.FileInfo) bool {
	return strings.HasSuffix(i.Name(), suffix)
}

func createFakeExecutable(name string) error {
	return os.WriteFile(name+suffix, []byte{}, 0o666)
}
