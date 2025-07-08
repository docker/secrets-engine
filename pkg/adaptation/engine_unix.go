//go:build !windows

package adaptation

import (
	"io/fs"
	"os"
)

func isExecutable(i os.FileInfo) bool {
	return i.Mode()&fs.FileMode(0o111) != 0
}
