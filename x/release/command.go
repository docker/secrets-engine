package main

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
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
	minor       bool
	major       bool
	noPropagate bool
}

func ReleaseCommand(cfg Config) (*cobra.Command, error) {
	opts := opts{}
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
			level, err := getLevel(opts)
			if err != nil {
				return err
			}
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
				return helper.BumpModule(mod, level, modData, &projectFS{opts: opts, logger: logging.NewDefaultLogger("")})
			}
			return helper.BumpIterative(mod, level, data, &projectFS{opts: opts, logger: logging.NewDefaultLogger("")})
		},
	}

	flags := bump.Flags()
	flags.BoolVar(&opts.dryRun, "dry", false, "Dry run: Only log all steps, no actual changes will be made.")
	flags.BoolVar(&opts.skipGit, "skip-git", false, "Skip git operations: Useful to preview only the go.mod changes.")
	flags.BoolVar(&opts.minor, "minor", false, "Do a minor release (downstream dependencies will only get a patch release bump).")
	flags.BoolVar(&opts.major, "major", false, "Do a major release (downstream dependencies will only get a patch release bump).")
	flags.BoolVar(&opts.noPropagate, "no-propagate", false, "Only release the specified module and do not propagate to internal downstream dependencies.")

	return bump, nil
}

func getLevel(opts opts) (helper.ReleaseLevel, error) {
	if opts.minor && opts.major {
		return -1, fmt.Errorf("cannot use both --minor and --major at the same time")
	}
	if opts.major {
		return helper.Major, nil
	}
	if opts.minor {
		return helper.Minor, nil
	}
	return helper.Patch, nil
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
	mod = path.Dir(f.Module.Mod.Path) + "/" + mod
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
	return gitTag(tag)
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
	entries, err := fs.ReadDir(root, ".")
	if err != nil {
		return nil, err
	}
	modules := helper.RepoData{}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		mod := entry.Name()
		if _, err := os.Stat(filepath.Join(mod, "go.mod")); err != nil {
			continue
		}
		latest, err := getLatestVersion(mod)
		if err != nil {
			return nil, err
		}
		v, extra := helper.CutVersionExtra(latest)
		if !slices.Contains(versionExtraAllowList, v) {
			extra = ""
		}
		data, err := helper.NewFutureVersions(v, helper.WithExtra(extra))
		if err != nil {
			return nil, err
		}
		deps, err := getDirectProjectDependencies(mod)
		if err != nil {
			return nil, err
		}
		modules.AddMod(mod, *data, deps)
	}
	return modules, nil
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
	project := path.Dir(f.Module.Mod.Path)
	for _, require := range f.Require {
		if strings.HasPrefix(require.Mod.Path, project) {
			deps = append(deps, strings.TrimPrefix(require.Mod.Path, project+"/"))
		}
	}
	return deps, nil
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
	if !strings.HasPrefix(latest, prefix) {
		return "", fmt.Errorf("unexptected format of latest release: %s", latest)
	}
	return strings.TrimPrefix(latest, prefix), nil
}

func gitTag(tag string) error {
	cmd := exec.Command("git", "tag", tag)
	return cmd.Run()
}

func gitCommit(commit string) error {
	cmd := exec.Command("git", "commit", "-m", commit)
	return cmd.Run()
}
