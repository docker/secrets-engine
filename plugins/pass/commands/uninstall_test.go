// Copyright 2026 Docker, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package commands

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUninstallCommandOptions(t *testing.T) {
	t.Parallel()
	for _, dir := range []string{"", "plugins", "./plugins"} {
		_, err := UninstallCommand(dir)
		assert.ErrorContains(t, err, "absolute path", dir)
	}
	cmd, err := UninstallCommand(t.TempDir())
	require.NoError(t, err)
	assert.Equal(t, "uninstall", cmd.Name())
}

func TestUninstallCommand(t *testing.T) {
	t.Parallel()
	pluginDir := func(t *testing.T, names ...string) string {
		t.Helper()
		dir := t.TempDir()
		for _, name := range names {
			require.NoError(t, os.WriteFile(filepath.Join(dir, exeName(name)), []byte("binary"), 0o755))
		}
		return dir
	}
	uninstall := func(t *testing.T, dir string, args ...string) (string, error) {
		t.Helper()
		return execute(t, newUninstallCommand(dir), nil, args...)
	}

	t.Run("deletes the plugin", func(t *testing.T) {
		t.Parallel()
		dir := pluginDir(t, "acme", "other")
		out, err := uninstall(t, dir, "acme")
		require.NoError(t, err, out)
		assert.Equal(t, []string{exeName("other")}, dirNames(t, dir))
		assert.Equal(t, "Uninstalled "+exeName("acme")+" from "+dir+"\nRestart the secrets engine to apply the change.\n", out)
	})
	t.Run("deletes several plugins", func(t *testing.T) {
		t.Parallel()
		dir := pluginDir(t, "acme", "other", "third")
		out, err := uninstall(t, dir, "third", "acme", "third")
		require.NoError(t, err, out)
		assert.Equal(t, []string{exeName("other")}, dirNames(t, dir))
		assert.Equal(t, "Uninstalled "+exeName("third")+" from "+dir+"\n"+
			"Uninstalled "+exeName("acme")+" from "+dir+"\n"+
			"Restart the secrets engine to apply the change.\n", out)
	})
	t.Run("missing plugin deletes nothing", func(t *testing.T) {
		t.Parallel()
		dir := pluginDir(t, "acme")
		out, err := uninstall(t, dir, "acme", "missing")
		require.ErrorIs(t, err, fs.ErrNotExist, out)
		assert.ErrorContains(t, err, "plugin missing is not installed in "+dir)
		assert.Equal(t, []string{exeName("acme")}, dirNames(t, dir))
	})
	t.Run("rejects a name with a directory", func(t *testing.T) {
		t.Parallel()
		parent := t.TempDir()
		dir := filepath.Join(parent, "plugins")
		require.NoError(t, os.Mkdir(dir, 0o755))
		outside := filepath.Join(parent, exeName("outside"))
		require.NoError(t, os.WriteFile(outside, []byte("keep"), 0o600))
		for _, name := range []string{"", ".", "..", "/", "../outside", outside} {
			out, err := uninstall(t, dir, name)
			assert.ErrorContains(t, err, "invalid plugin name", name, out)
		}
		assert.FileExists(t, outside)
	})
	t.Run("refuses a directory", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		sub := filepath.Join(dir, exeName("acme"))
		require.NoError(t, os.Mkdir(sub, 0o755))
		out, err := uninstall(t, dir, "acme")
		assert.ErrorContains(t, err, "is a directory, not a plugin", out)
		assert.DirExists(t, sub)
	})
	t.Run("requires a name", func(t *testing.T) {
		t.Parallel()
		dir := pluginDir(t, "acme")
		out, err := uninstall(t, dir, []string{}...)
		assert.ErrorContains(t, err, "requires at least 1 arg", out)
		assert.Equal(t, []string{exeName("acme")}, dirNames(t, dir))
	})
}

func TestUninstallCommandHintsSudo(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a directory the current user cannot write to")
	}
	t.Parallel()
	pluginDir := t.TempDir()
	path := filepath.Join(pluginDir, "myplugin")
	require.NoError(t, os.WriteFile(path, []byte("binary"), 0o755))
	require.NoError(t, os.Chmod(pluginDir, 0o555))
	t.Cleanup(func() { _ = os.Chmod(pluginDir, 0o755) })

	out, err := execute(t, newUninstallCommand(pluginDir), nil, "myplugin")
	require.ErrorIs(t, err, fs.ErrPermission, out)
	assert.Equal(t, "Error: remove "+path+": permission denied\n\n"+sudoHint+"\n", out)
	assert.FileExists(t, path)
}
