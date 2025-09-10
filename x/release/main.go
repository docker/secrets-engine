package main

import (
	"context"
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
	return cmd.Run()
}
