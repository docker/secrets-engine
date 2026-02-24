// Copyright 2025-2026 Docker, Inc.
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

package main

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/mod/modfile"

	"github.com/docker/secrets-engine/x/logging"
	"github.com/docker/secrets-engine/x/release/helper"
)

type Config struct {
	EnableModulesWithPreReleaseVersion []string
	BeforeCommitHook                   func() error
}

type opts struct {
	dryRun      bool
	skipGit     bool
	level       helper.Level
	noPropagate bool
}

func ReleaseCommand(cfg Config) (*cobra.Command, error) {
	opts := opts{level: helper.Patch}
	if _, err := os.Stat(".git"); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("not in a git repository root directory")
		}
		return nil, err
	}
	bump := &cobra.Command{
		Use:  "bump [OPTIONS] <module>",
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			mod := args[0]
			data, err := newRepoData(cfg.EnableModulesWithPreReleaseVersion)
			if err != nil {
				return err
			}
			if _, ok := data[mod]; !ok {
				return fmt.Errorf("module %s not found", mod)
			}
			if opts.noPropagate {
				modData, ok := data[mod]
				if !ok {
					return fmt.Errorf("module %s not found", mod)
				}
				return helper.BumpModule(mod, opts.level, modData, &projectFS{opts: opts, beforeCommitHook: cfg.BeforeCommitHook, logger: logging.NewDefaultLogger("")})
			}
			return helper.BumpIterative(mod, opts.level, data, &projectFS{opts: opts, beforeCommitHook: cfg.BeforeCommitHook, logger: logging.NewDefaultLogger("")})
		},
	}

	flags := bump.Flags()
	flags.BoolVar(&opts.dryRun, "dry", false, "Dry run: Only log all steps, no actual changes will be made.")
	flags.BoolVar(&opts.skipGit, "skip-git", false, "Skip git operations: Useful to preview only the go.mod changes.")
	flags.Var(&opts.level, "release", fmt.Sprintf("Release type (default=patch): %s", helper.AllowedLevels()))
	flags.BoolVar(&opts.noPropagate, "no-propagate", false, "Only release the specified module and do not propagate to internal downstream dependencies.")

	return bump, nil
}

type projectFS struct {
	opts
	logger           logging.Logger
	beforeCommitHook func() error
}

func (m projectFS) BumpModInFile(filename, mod, version string) (bool, error) {
	modFileData, err := os.ReadFile(filename)
	if err != nil {
		return false, err
	}
	f, err := modfile.Parse(filename, modFileData, nil)
	if err != nil {
		return false, err
	}
	base, err := getModBase(f.Module.Mod.Path)
	if err != nil {
		return false, err
	}
	mod = base + "/" + mod
	needsAction := false
	for _, require := range f.Require {
		if require.Indirect {
			continue
		}
		if strings.HasPrefix(require.Mod.Path, mod) {
			oldVersion := require.Mod.Version
			require.Mod.Version = version
			needsAction = true
			m.logger.Printf("[%s] Bumping %s: %s -> %s", filename, mod, oldVersion, version)
			break
		}
	}

	if !needsAction {
		return needsAction, nil
	}
	f.SetRequire(f.Require)
	out, err := f.Format()
	if err != nil {
		return needsAction, err
	}

	if m.dryRun {
		return needsAction, nil
	}

	perm := fs.FileMode(0o644)
	if fi, err := os.Stat(filename); err == nil {
		perm = fi.Mode().Perm()
	}
	return needsAction, os.WriteFile(filename, out, perm)
}

func (m projectFS) GitTag(tag string) error {
	var prefix string
	if m.skipGit {
		prefix = "[skip] "
	}
	m.logger.Printf(prefix+"git tag: '%s'", tag)
	if m.dryRun || m.skipGit {
		return nil
	}
	if err := gitTag(tag); err != nil {
		return err
	}
	if !m.noPropagate && !m.dryRun {
		return gitPushTags()
	}
	return nil
}

func (m projectFS) GitCommit(commit string) error {
	if !m.dryRun && m.beforeCommitHook != nil {
		if err := m.beforeCommitHook(); err != nil {
			return err
		}
	}
	var prefix string
	if m.skipGit {
		prefix = "[skip] "
	}
	m.logger.Printf(prefix+"git commit: '%s'", commit)
	if m.dryRun || m.skipGit {
		return nil
	}
	return gitCommit(commit)
}

func newRepoData(versionExtraAllowList []string) (helper.RepoData, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return helper.RepoData{}, err
	}
	root := os.DirFS(cwd)
	modules := helper.RepoData{}
	err = fs.WalkDir(root, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Type()&fs.ModeSymlink != 0 {
			return fs.SkipDir
		}
		if !d.IsDir() {
			return nil
		}
		mod := path
		if _, err := os.Stat(filepath.Join(mod, "go.mod")); err != nil {
			return nil
		}
		latest, err := getLatestVersion(mod)
		if err != nil {
			return err
		}
		deps, err := getDirectProjectDependencies(mod)
		if err != nil {
			return err
		}
		modules.AddMod(mod, helper.Version{Current: latest, KeepExtra: slices.Contains(versionExtraAllowList, mod)}, deps)
		return nil
	})
	return modules, err
}

func getDirectProjectDependencies(mod string) ([]string, error) {
	modPath := filepath.Join(mod, "go.mod")
	data, err := os.ReadFile(filepath.Join(mod, "go.mod"))
	if err != nil {
		return nil, err
	}
	f, err := modfile.Parse(modPath, data, nil)
	if err != nil {
		return nil, err
	}
	var deps []string
	base, err := getModBase(f.Module.Mod.Path)
	if err != nil {
		return nil, err
	}
	for _, require := range f.Require {
		if strings.HasPrefix(require.Mod.Path, base) {
			deps = append(deps, strings.TrimPrefix(require.Mod.Path, base+"/"))
		}
	}
	return deps, nil
}

func getModBase(modPath string) (string, error) {
	parts := strings.SplitN(modPath, "/", 4)
	if len(parts) != 4 {
		return "", fmt.Errorf("unexpected module format: %s", modPath)
	}
	return strings.Join(parts[:3], "/"), nil
}

func getLatestVersion(modName string) (string, error) {
	cmd := exec.Command("git", "tag", "-l", modName+"/v*", "--sort=-v:refname")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(out), "\n")
	if len(lines) == 0 {
		return "", fmt.Errorf("no releases")
	}
	latest := strings.TrimSpace(lines[0])
	prefix := modName + "/"

	if latest == "" {
		latest = prefix + "v0.0.0"
	}

	if !strings.HasPrefix(latest, prefix) {
		return "", fmt.Errorf("unexptected format of latest release: %s", latest)
	}
	return strings.TrimPrefix(latest, prefix), nil
}

func gitTag(tag string) error {
	cmd := exec.Command("git", "tag", tag, "-m", tag)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git tag (%s): %s", err, string(out))
	}
	return nil
}

func gitPushTags() error {
	cmd := exec.Command("git", "push", "--tags")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git push --tags (%s): %s", err, string(out))
	}
	return nil
}

func gitCommit(commit string) error {
	cmd := exec.Command("git", "commit", "-am", commit)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git commit (%s): %s", err, string(out))
	}
	return nil
}
