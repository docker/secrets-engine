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
	"debug/buildinfo"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/spf13/cobra"
)

const pluginSDKModule = "github.com/docker/secrets-engine/plugin"

const sudoHint = "Rerun the command with sudo."

const sudoPathHint = `If Go is installed, sudo dropped it from PATH. Rerun the command with sudo PATH="$PATH".`

//go:embed install_example.md
var installExample string

//go:embed install_long.md
var installLong string

type installOpts struct {
	pluginDir string
	name      string
}

// InstallCommand builds a plugin from Go source and installs it into
// pluginDir, the directory the secrets engine launches plugins from. The
// engine scans that directory only at startup and takes each file name as the
// plugin name.
func InstallCommand(pluginDir string) (*cobra.Command, error) {
	if !filepath.IsAbs(pluginDir) {
		return nil, fmt.Errorf("plugin directory must be an absolute path, got %q", pluginDir)
	}
	return newInstallCommand(installOpts{pluginDir: pluginDir}), nil
}

func newInstallCommand(opts installOpts) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "install PACKAGE",
		Short:   "Build a plugin from Go source and install it into the plugin directory.",
		Long:    strings.Trim(installLong, "\n"),
		Example: strings.Trim(installExample, "\n"),
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInstall(cmd, opts, args[0])
		},
	}
	cmd.Flags().StringVar(&opts.name, "name", "", "Install the plugin as `NAME` instead of the binary's default name.")
	return cmd
}

func runInstall(cmd *cobra.Command, opts installOpts, arg string) error {
	if err := checkPluginName(opts.name); err != nil {
		return err
	}
	target, err := parseBuildTarget(arg)
	if err != nil {
		return err
	}
	stage, err := os.MkdirTemp(opts.pluginDir, ".install-*")
	if errors.Is(err, fs.ErrPermission) {
		err = fmt.Errorf("installing to %s: %w", opts.pluginDir, fs.ErrPermission)
	}
	if err != nil {
		return withSudoHint(err)
	}
	defer func() { _ = os.RemoveAll(stage) }()

	gobin, err := os.MkdirTemp("", "docker-pass-install-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(gobin) }()

	if err := goInstall(cmd, target, gobin); err != nil {
		return fmt.Errorf("building %s: %w", arg, err)
	}
	built, err := os.ReadDir(gobin)
	if err != nil {
		return err
	}
	if len(built) == 0 {
		return fmt.Errorf("%s is not a main package: go install produced no binary", arg)
	}
	name := pluginFileName(opts.name, built[0].Name())
	staged := filepath.Join(stage, name)
	if err := copyExecutable(filepath.Join(gobin, built[0].Name()), staged); err != nil {
		return err
	}
	info, err := buildinfo.ReadFile(staged)
	if err != nil {
		return fmt.Errorf("reading build info of %s: %w", arg, err)
	}
	if !usesPluginSDK(info) {
		return fmt.Errorf("%s is not a secrets engine plugin: it does not use %s", arg, pluginSDKModule)
	}

	dst := filepath.Join(opts.pluginDir, name)
	if err := os.Rename(staged, dst); err != nil {
		return err
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "Installed %s (%s %s, %s) to %s\nRestart the secrets engine to load it.\n",
		name, info.Main.Path, info.Main.Version, info.GoVersion, dst)
	return err
}

func withSudoHint(err error) error {
	if errors.Is(err, fs.ErrPermission) && runtime.GOOS != "windows" && os.Geteuid() != 0 {
		return fmt.Errorf("%w\n\n%s", err, sudoHint)
	}
	return err
}

type buildTarget struct {
	dir string
	pkg string
}

func parseBuildTarget(arg string) (buildTarget, error) {
	if strings.Contains(arg, "...") {
		return buildTarget{}, fmt.Errorf("%s: patterns are not supported, name one main package", arg)
	}
	if !filepath.IsAbs(arg) && !strings.HasPrefix(arg, ".") {
		if !strings.Contains(arg, "@") {
			arg += "@latest"
		}
		return buildTarget{pkg: arg}, nil
	}
	dir, err := filepath.Abs(arg)
	if err != nil {
		return buildTarget{}, err
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return buildTarget{}, err
	}
	if !fi.IsDir() {
		return buildTarget{}, fmt.Errorf("%s: not a directory", arg)
	}
	return buildTarget{dir: dir, pkg: "."}, nil
}

func goInstall(cmd *cobra.Command, target buildTarget, gobin string) error {
	env := slices.DeleteFunc(os.Environ(), func(kv string) bool {
		key, _, _ := strings.Cut(kv, "=")
		return strings.EqualFold(key, "GOOS") || strings.EqualFold(key, "GOARCH")
	})
	goCmd := exec.CommandContext(cmd.Context(), "go", "install", target.pkg)
	goCmd.Dir = target.dir
	goCmd.Env = append(env, "GOBIN="+gobin)
	goCmd.Stdout = cmd.ErrOrStderr()
	goCmd.Stderr = cmd.ErrOrStderr()
	if err := deescalate(goCmd, gobin); err != nil {
		return err
	}
	err := goCmd.Run()
	if errors.Is(err, exec.ErrNotFound) {
		err = fmt.Errorf("the Go toolchain is required to build plugins: %w", err)
		if underSudo() {
			err = fmt.Errorf("%w\n\n%s", err, sudoPathHint)
		}
	}
	return err
}

func underSudo() bool {
	return os.Geteuid() == 0 && os.Getenv("SUDO_UID") != ""
}

func usesPluginSDK(info *buildinfo.BuildInfo) bool {
	for _, dep := range info.Deps {
		if dep.Path == pluginSDKModule {
			return true
		}
	}
	return info.Main.Path == pluginSDKModule
}

func checkPluginName(name string) error {
	if name == "" || isFileName(name) {
		return nil
	}
	return fmt.Errorf("invalid --name %q: want a file name without a directory", name)
}

func isFileName(name string) bool {
	return name != "." && filepath.IsLocal(name) && name == filepath.Base(name)
}

func pluginFileName(name, built string) string {
	if name == "" {
		return built
	}
	return withExeSuffix(name)
}

func withExeSuffix(name string) string {
	if runtime.GOOS == "windows" && !strings.EqualFold(filepath.Ext(name), ".exe") {
		name += ".exe"
	}
	return name
}

func copyExecutable(src, dst string) error {
	// Copy rather than rename: os.Rename fails across filesystems (e.g. tmpfs
	// to ext4). src is the go install output in the system temp directory,
	// which is often tmpfs.
	if err := copyFile(src, dst); err != nil {
		return err
	}
	return os.Chmod(dst, 0o755)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
