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
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	stdinReaderModule = "github.com/docker/secrets-engine/plugins/stdinreader"
	toolMain          = "package main\n\nfunc main() {}\n"
)

func TestInstallCommandOptions(t *testing.T) {
	t.Parallel()
	for _, dir := range []string{"", "plugins", "./plugins"} {
		_, err := InstallCommand(dir)
		assert.ErrorContains(t, err, "absolute path", dir)
	}
	cmd, err := InstallCommand(t.TempDir())
	require.NoError(t, err)
	assert.Equal(t, "install", cmd.Name())
}

func TestParseBuildTarget(t *testing.T) {
	t.Parallel()
	wd, err := os.Getwd()
	require.NoError(t, err)
	dir := t.TempDir()
	file := filepath.Join(dir, "main.go")
	require.NoError(t, os.WriteFile(file, nil, 0o600))

	tests := []struct {
		name string
		arg  string
		want buildTarget
	}{
		{"absolute directory", dir, buildTarget{dir: dir, pkg: "."}},
		{"current directory", ".", buildTarget{dir: wd, pkg: "."}},
		{"relative directory", "./internal", buildTarget{dir: filepath.Join(wd, "internal"), pkg: "."}},
		{"package path", "example.com/acme/plugin", buildTarget{pkg: "example.com/acme/plugin@latest"}},
		{"package path with version", "example.com/acme/plugin@v1.2.0", buildTarget{pkg: "example.com/acme/plugin@v1.2.0"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseBuildTarget(tc.arg)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
	t.Run("missing directory", func(t *testing.T) {
		_, err := parseBuildTarget(filepath.Join(dir, "missing"))
		assert.ErrorIs(t, err, fs.ErrNotExist)
	})
	t.Run("file", func(t *testing.T) {
		_, err := parseBuildTarget(file)
		assert.ErrorContains(t, err, "not a directory")
	})
	t.Run("pattern", func(t *testing.T) {
		for _, arg := range []string{"./...", "example.com/acme/...", "example.com/acme/...@latest"} {
			_, err := parseBuildTarget(arg)
			assert.ErrorContains(t, err, "patterns are not supported", arg)
		}
	})
}

func TestUsesPluginSDK(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		info debug.BuildInfo
		want bool
	}{
		{"main module", debug.BuildInfo{Main: debug.Module{Path: pluginSDKModule}}, true},
		{"dependency", debug.BuildInfo{Deps: []*debug.Module{{Path: "example.com/other"}, {Path: pluginSDKModule, Version: "v0.3.4"}}}, true},
		{"replaced dependency", debug.BuildInfo{Deps: []*debug.Module{{Path: pluginSDKModule, Replace: &debug.Module{Path: "../plugin"}}}}, true},
		{"unrelated", debug.BuildInfo{Main: debug.Module{Path: "example.com/tool"}, Deps: []*debug.Module{{Path: "example.com/other"}}}, false},
		{"longer module path", debug.BuildInfo{Deps: []*debug.Module{{Path: pluginSDKModule + "s/pass"}}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, usesPluginSDK(&tc.info))
		})
	}
}

func TestCheckPluginName(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"", "acme", "acme-plugin.v2"} {
		assert.NoError(t, checkPluginName(name), name)
	}
	for _, name := range []string{".", "..", "dir/acme", "/acme", "acme/"} {
		assert.ErrorContains(t, checkPluginName(name), "invalid --name", name)
	}
}

func TestInstallCommand(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not on PATH")
	}
	plugin := filepath.Join("..", "..", "stdinreader")
	if _, err := os.Stat(plugin); err != nil {
		t.Skip("stdinreader plugin not found next to this module")
	}
	t.Setenv("GOFLAGS", "-buildvcs=false")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("GOPROXY", "off")

	install := func(t *testing.T, args ...string) (pluginDir, out string, err error) {
		t.Helper()
		pluginDir = t.TempDir()
		out, err = execute(t, newInstallCommand(installOpts{pluginDir: pluginDir}), nil, args...)
		return pluginDir, out, err
	}

	t.Run("installs the stdinreader plugin", func(t *testing.T) {
		pluginDir, out, err := install(t, plugin)
		require.NoError(t, err, out)
		installed := filepath.Join(pluginDir, exeName("stdinreader"))
		assert.Equal(t, []string{exeName("stdinreader")}, dirNames(t, pluginDir))
		if runtime.GOOS != "windows" {
			fi, err := os.Stat(installed)
			require.NoError(t, err)
			assert.Equal(t, fs.FileMode(0o755), fi.Mode().Perm())
		}
		assert.Contains(t, out, "Installed "+exeName("stdinreader")+" ("+stdinReaderModule+" ")
		assert.Contains(t, out, " to "+installed+"\nRestart the secrets engine to load it.\n")
	})
	t.Run("--name renames the plugin", func(t *testing.T) {
		pluginDir, out, err := install(t, plugin, "--name", "acme")
		require.NoError(t, err, out)
		assert.Equal(t, []string{exeName("acme")}, dirNames(t, pluginDir))
	})
	t.Run("rejects an invalid --name before building", func(t *testing.T) {
		pluginDir, out, err := install(t, filepath.Join(plugin, "missing"), "--name", "dir/acme")
		assert.ErrorContains(t, err, "invalid --name", out)
		assert.Empty(t, dirNames(t, pluginDir))
	})
	t.Run("replaces an existing plugin", func(t *testing.T) {
		pluginDir := t.TempDir()
		installed := filepath.Join(pluginDir, exeName("stdinreader"))
		require.NoError(t, os.WriteFile(installed, []byte("old"), 0o600))
		out, err := execute(t, newInstallCommand(installOpts{pluginDir: pluginDir}), nil, plugin)
		require.NoError(t, err, out)
		fi, err := os.Stat(installed)
		require.NoError(t, err)
		assert.Greater(t, fi.Size(), int64(len("old")))
		assert.Equal(t, []string{exeName("stdinreader")}, dirNames(t, pluginDir))
	})
	t.Run("builds for the host despite GOOS and GOARCH", func(t *testing.T) {
		t.Setenv("GOOS", "plan9")
		t.Setenv("GOARCH", "386")
		pluginDir, out, err := install(t, plugin)
		require.NoError(t, err, out)
		assert.Equal(t, []string{exeName("stdinreader")}, dirNames(t, pluginDir))
	})
	t.Run("compile error", func(t *testing.T) {
		broken := writeModule(t, "package main\n\nfunc main() { missing() }\n")
		pluginDir, out, err := install(t, broken)
		assert.ErrorContains(t, err, "building "+broken, out)
		assert.Contains(t, out, "undefined: missing")
		assert.Empty(t, dirNames(t, pluginDir))
	})
	t.Run("library package", func(t *testing.T) {
		lib := writeModule(t, "package tool\n")
		pluginDir, out, err := install(t, lib)
		assert.ErrorContains(t, err, "is not a main package", out)
		assert.Empty(t, dirNames(t, pluginDir))
	})
	t.Run("binary without the plugin SDK", func(t *testing.T) {
		tool := writeModule(t, toolMain)
		pluginDir, out, err := install(t, tool)
		assert.ErrorContains(t, err, "is not a secrets engine plugin", out)
		assert.Empty(t, dirNames(t, pluginDir))
	})
}

func TestPlaceElevates(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a directory the current user cannot write to")
	}
	t.Parallel()
	src := filepath.Join(t.TempDir(), "myplugin")
	require.NoError(t, os.WriteFile(src, []byte("binary"), 0o600))
	pluginDir := t.TempDir()
	require.NoError(t, os.Chmod(pluginDir, 0o555))
	dst := filepath.Join(pluginDir, "myplugin")

	var elevated []string
	opts := installOpts{elevate: func(_ *cobra.Command, from, to string) error {
		elevated = append(elevated, from, to)
		return nil
	}}
	require.NoError(t, place(&cobra.Command{}, opts, src, dst))
	assert.Equal(t, []string{src, dst}, elevated)
	assert.Empty(t, dirNames(t, pluginDir))
}

func writeModule(t *testing.T, src string) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/acme/tool\n\ngo 1.21\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o600))
	return dir
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func exeName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}
