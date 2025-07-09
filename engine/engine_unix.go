//go:build !windows

package engine

import (
	"io/fs"
	"os"
)

func isExecutable(i os.FileInfo) bool {
	return i.Mode()&fs.FileMode(0o111) != 0
}
