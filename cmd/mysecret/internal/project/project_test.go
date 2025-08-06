package project

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_findGitProjectRoot(t *testing.T) {
	t.Parallel()
	t.Run("not in a git repository", func(t *testing.T) {
		_, err := findGitProjectRoot(t.TempDir())
		assert.ErrorIs(t, err, ErrNotInGitRepo)
	})
	t.Run("in a git repository", func(t *testing.T) {
		t.Run("in top level directory", func(t *testing.T) {
			dir := t.TempDir()
			assert.NoError(t, os.Mkdir(filepath.Join(dir, ".git"), 0o755))
			result, err := findGitProjectRoot(dir)
			assert.NoError(t, err)
			assert.Equal(t, dir, result)
		})
		t.Run("in deep directory", func(t *testing.T) {
			dir := t.TempDir()
			assert.NoError(t, os.Mkdir(filepath.Join(dir, ".git"), 0o755))
			nestedDir := filepath.Join(dir, "foo", "bar")
			assert.NoError(t, os.MkdirAll(nestedDir, 0o755))
			result, err := findGitProjectRoot(dir)
			assert.NoError(t, err)
			assert.Equal(t, dir, result)
		})
	})
}
