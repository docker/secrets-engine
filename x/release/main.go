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
	"context"
	"fmt"
	"os/exec"
	"syscall"

	"github.com/docker/secrets-engine/x/oshelper"
)

func main() {
	ctx, cancel := oshelper.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	cmd, err := ReleaseCommand(Config{EnableModulesWithPreReleaseVersion: []string{"x"}, BeforeCommitHook: makeMod})
	if err != nil {
		panic(err)
	}
	cmd.SetContext(ctx)
	if err := cmd.Execute(); err != nil {
		panic(err)
	}
}

func makeMod() error {
	cmd := exec.Command("make", "mod")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("make mod (%s): %s", err, string(out))
	}
	return nil
}
