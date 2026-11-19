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
	_ "embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/spf13/cobra"
)

//go:embed uninstall_example.md
var uninstallExample string

//go:embed uninstall_long.md
var uninstallLong string

type uninstallOpts struct {
	pluginDir string
	elevate   func(cmd *cobra.Command, path string) error
}

// UninstallCommand deletes plugins from pluginDir, the directory the secrets
// engine launches plugins from. The engine scans that directory only at
// startup, so a deleted plugin keeps running until the engine restarts.
func UninstallCommand(pluginDir string) (*cobra.Command, error) {
	if !filepath.IsAbs(pluginDir) {
		return nil, fmt.Errorf("plugin directory must be an absolute path, got %q", pluginDir)
	}
	return newUninstallCommand(uninstallOpts{
		pluginDir: pluginDir,
		elevate:   sudoRemove,
	}), nil
}

func newUninstallCommand(opts uninstallOpts) *cobra.Command {
	return &cobra.Command{
		Use:     "uninstall NAME [NAME...]",
		Short:   "Delete plugins from the plugin directory.",
		Long:    strings.Trim(uninstallLong, "\n"),
		Example: strings.Trim(uninstallExample, "\n"),
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUninstall(cmd, opts, args)
		},
	}
}

func runUninstall(cmd *cobra.Command, opts uninstallOpts, names []string) error {
	var paths []string
	for _, name := range names {
		path, err := pluginPath(opts.pluginDir, name)
		if err != nil {
			return err
		}
		if !slices.Contains(paths, path) {
			paths = append(paths, path)
		}
	}
	for _, path := range paths {
		if err := remove(cmd, opts, path); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Uninstalled %s from %s\n", filepath.Base(path), opts.pluginDir); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(cmd.OutOrStdout(), "Restart the secrets engine to apply the change.")
	return err
}

func pluginPath(dir, name string) (string, error) {
	if !isFileName(name) {
		return "", fmt.Errorf("invalid plugin name %q: want a file name without a directory", name)
	}
	path := filepath.Join(dir, withExeSuffix(name))
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("plugin %s is not installed in %s: %w", name, dir, fs.ErrNotExist)
	}
	if err != nil {
		return "", err
	}
	if fi.IsDir() {
		return "", fmt.Errorf("%s is a directory, not a plugin", path)
	}
	return path, nil
}

func remove(cmd *cobra.Command, opts uninstallOpts, path string) error {
	err := os.Remove(path)
	if errors.Is(err, fs.ErrPermission) {
		return opts.elevate(cmd, path)
	}
	return err
}

func sudoRemove(cmd *cobra.Command, path string) error {
	dir := filepath.Dir(path)
	if runtime.GOOS == "windows" {
		return fmt.Errorf("removing from %s: %w", dir, fs.ErrPermission)
	}
	return sudoRun(cmd, "Removing from "+dir, "rm", "--", path)
}
