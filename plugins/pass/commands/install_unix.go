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

//go:build !windows

package commands

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
)

func deescalate(goCmd *exec.Cmd, gobin string) error {
	if !underSudo() {
		return nil
	}
	caller, err := user.LookupId(os.Getenv("SUDO_UID"))
	if err != nil {
		return fmt.Errorf("looking up the user who ran sudo: %w", err)
	}
	uid, err := strconv.ParseUint(caller.Uid, 10, 32)
	if err != nil {
		return err
	}
	gid, err := strconv.ParseUint(caller.Gid, 10, 32)
	if err != nil {
		return err
	}
	if err := os.Lchown(gobin, int(uid), int(gid)); err != nil {
		return err
	}
	goCmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	goCmd.Env = append(goCmd.Env, "HOME="+caller.HomeDir, "USER="+caller.Username, "LOGNAME="+caller.Username)
	return nil
}
