//go:build !windows

package runtime

import (
	"io/fs"
	"os"
)

const suffix = ""

func isExecutable(i os.FileInfo) bool {
	return i.Mode()&fs.FileMode(0o111) != 0
}

func createFakeExecutable(name string) error {
	return os.WriteFile(name, []byte{}, 0o755)
}
