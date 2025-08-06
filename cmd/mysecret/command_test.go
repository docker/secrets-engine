package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/cmd/mysecret/internal/project"
)

func Test_WithProjectContextHandling(t *testing.T) {
	t.Run("fails if --global is not set and not in a git dir", func(t *testing.T) {
		t.Chdir(t.TempDir())

		cmd := rootCommand(t.Context())
		cmd.AddCommand(WithProjectContextHandling(&cobra.Command{Use: "a", Args: cobra.NoArgs, Run: func(*cobra.Command, []string) {}}))
		cmd.SetArgs([]string{"a"})

		assert.ErrorIs(t, cmd.Execute(), project.ErrNotInGitRepo)
	})
	t.Run("no project in context when --global is set and in a git dir", func(t *testing.T) {
		dir := t.TempDir()
		assert.NoError(t, os.Mkdir(filepath.Join(dir, ".git"), 0o755))
		t.Chdir(dir)

		var proj project.Project
		var runErr error
		ctxRun := func(cmd *cobra.Command, _ []string) {
			ctx := cmd.Context()
			proj, runErr = project.FromContext(ctx)
		}

		cmd := rootCommand(t.Context())
		cmd.AddCommand(WithProjectContextHandling(&cobra.Command{Use: "a", Args: cobra.NoArgs, Run: ctxRun}))
		cmd.SetArgs([]string{"a", "--global"})

		assert.NoError(t, cmd.Execute())
		assert.ErrorIs(t, runErr, project.ErrNotInGitRepo)
		assert.Nil(t, proj)
	})
	t.Run("project in context when in a git dir", func(t *testing.T) {
		dir := t.TempDir()
		assert.NoError(t, os.Mkdir(filepath.Join(dir, ".git"), 0o755))
		t.Chdir(dir)

		var proj project.Project
		var runErr error
		ctxRun := func(cmd *cobra.Command, _ []string) {
			ctx := cmd.Context()
			proj, runErr = project.FromContext(ctx)
		}

		cmd := rootCommand(t.Context())
		cmd.AddCommand(WithProjectContextHandling(&cobra.Command{Use: "a", Args: cobra.NoArgs, Run: ctxRun}))
		cmd.SetArgs([]string{"a"})

		assert.NoError(t, cmd.Execute())
		assert.NoError(t, runErr)
		require.NotNil(t, proj)
		assert.Equal(t, dir, proj.Dir())
	})
}
