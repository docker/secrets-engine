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

//go:embed install_example.md
var installExample string

//go:embed install_long.md
var installLong string

type installOpts struct {
	pluginDir string
	name      string
	elevate   func(cmd *cobra.Command, src, dst string) error
}

// InstallCommand builds a plugin from Go source and installs it into
// pluginDir, the directory the secrets engine launches plugins from. The
// engine scans that directory only at startup and takes each file name as the
// plugin name.
func InstallCommand(pluginDir string) (*cobra.Command, error) {
	if !filepath.IsAbs(pluginDir) {
		return nil, fmt.Errorf("plugin directory must be an absolute path, got %q", pluginDir)
	}
	return newInstallCommand(installOpts{
		pluginDir: pluginDir,
		elevate:   sudoInstall,
	}), nil
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
	stage, err := os.MkdirTemp("", "docker-pass-install-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(stage) }()

	if err := goInstall(cmd, target, stage); err != nil {
		return fmt.Errorf("building %s: %w", arg, err)
	}
	built, err := os.ReadDir(stage)
	if err != nil {
		return err
	}
	if len(built) == 0 {
		return fmt.Errorf("%s is not a main package: go install produced no binary", arg)
	}
	src := filepath.Join(stage, built[0].Name())
	info, err := buildinfo.ReadFile(src)
	if err != nil {
		return fmt.Errorf("reading build info of %s: %w", arg, err)
	}
	if !usesPluginSDK(info) {
		return fmt.Errorf("%s is not a secrets engine plugin: it does not use %s", arg, pluginSDKModule)
	}

	name := pluginFileName(opts.name, built[0].Name())
	dst := filepath.Join(opts.pluginDir, name)
	if err := place(cmd, opts, src, dst); err != nil {
		return err
	}
	_, err = fmt.Fprintf(cmd.OutOrStdout(), "Installed %s (%s %s, %s) to %s\nRestart the secrets engine to load it.\n",
		name, info.Main.Path, info.Main.Version, info.GoVersion, dst)
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
	err := goCmd.Run()
	if errors.Is(err, exec.ErrNotFound) {
		return fmt.Errorf("the Go toolchain is required to build plugins: %w", err)
	}
	return err
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
	if name == "" || (name == filepath.Base(name) && name != "." && name != "..") {
		return nil
	}
	return fmt.Errorf("invalid --name %q: want a file name without a directory", name)
}

func pluginFileName(name, built string) string {
	if name == "" {
		return built
	}
	if runtime.GOOS == "windows" && !strings.EqualFold(filepath.Ext(name), ".exe") {
		name += ".exe"
	}
	return name
}

func place(cmd *cobra.Command, opts installOpts, src, dst string) error {
	err := copyExecutable(src, dst)
	if errors.Is(err, fs.ErrPermission) {
		return opts.elevate(cmd, src, dst)
	}
	return err
}

func copyExecutable(src, dst string) error {
	tmpDir, err := os.MkdirTemp(filepath.Dir(dst), ".install-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	tmp := filepath.Join(tmpDir, filepath.Base(dst))
	// Copy rather than rename: os.Rename fails across filesystems (e.g. tmpfs
	// to ext4). src is the go install output in the system temp directory,
	// which is often tmpfs.
	if err := copyFile(src, tmp); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
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

// sudoInstall copies src to dst as root; this process stays unprivileged.
// sudo, being setuid-root, prompts for the password on the terminal itself,
// so the password never passes through here. Without a terminal it fails.
func sudoInstall(cmd *cobra.Command, src, dst string) error {
	if runtime.GOOS == "windows" {
		return fmt.Errorf("installing to %s: %w", filepath.Dir(dst), fs.ErrPermission)
	}
	args := []string{"install", "-m", "0755", src, dst}
	_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Installing to %s requires root; running: sudo %s\n", filepath.Dir(dst), strings.Join(args, " "))
	sudo := exec.CommandContext(cmd.Context(), "sudo", args...)
	sudo.Stdin = cmd.InOrStdin()
	sudo.Stdout = cmd.OutOrStdout()
	sudo.Stderr = cmd.ErrOrStderr()
	if err := sudo.Run(); err != nil {
		return fmt.Errorf("sudo install: %w", err)
	}
	return nil
}
