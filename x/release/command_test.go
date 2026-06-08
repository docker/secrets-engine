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

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Not parallel: the git helpers shell out in the process working directory, so
// the test switches cwd, which is process-global.
func Test_verifyReleaseRef(t *testing.T) {
	repo := newGitRepoWithRemote(t)

	t.Run("passes when HEAD is at remote default tip", func(t *testing.T) {
		assert.NoError(t, verifyReleaseRef(repo.ctxAt(t)))
	})

	t.Run("fails on a local-only commit", func(t *testing.T) {
		repo.commit(t, "chore: bump local/v0.0.1")
		err := verifyReleaseRef(repo.ctxAt(t))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "refusing to tag")
	})

	t.Run("passes again once the commit is pushed", func(t *testing.T) {
		// Self-contained: put HEAD ahead of the remote, assert it fails, then
		// push and assert it recovers — so the fail -> push -> pass sequence is
		// exercised even when this subtest is run in isolation.
		repo.commit(t, "chore: bump local/v0.0.2")
		require.Error(t, verifyReleaseRef(repo.ctxAt(t)))

		repo.run(t, "push", "origin", "HEAD:main")
		assert.NoError(t, verifyReleaseRef(repo.ctxAt(t)))
	})
}

type gitRepo struct {
	dir string
}

// newGitRepoWithRemote creates a working clone whose origin is a local bare
// repo, with origin/HEAD pointing at main, and HEAD at the remote tip.
func newGitRepoWithRemote(t *testing.T) *gitRepo {
	t.Helper()
	root := t.TempDir()
	bare := filepath.Join(root, "origin.git")
	work := filepath.Join(root, "work")

	runGitIn(t, root, "init", "--bare", "--initial-branch=main", bare)

	r := &gitRepo{dir: work}
	runGitIn(t, root, "clone", bare, work)
	r.config(t)
	require.NoError(t, os.WriteFile(filepath.Join(work, "README.md"), []byte("seed\n"), 0o644))
	r.run(t, "add", "README.md")
	r.run(t, "commit", "-m", "seed")
	r.run(t, "push", "-u", "origin", "main")
	// Make origin/HEAD resolvable so remoteDefaultBranch finds it.
	r.run(t, "remote", "set-head", "origin", "main")
	return r
}

func (r *gitRepo) config(t *testing.T) {
	t.Helper()
	r.run(t, "config", "user.email", "test@example.com")
	r.run(t, "config", "user.name", "test")
	r.run(t, "config", "commit.gpgsign", "false")
	r.run(t, "config", "tag.gpgsign", "false")
}

func (r *gitRepo) commit(t *testing.T, msg string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(r.dir, "file.txt"), []byte(msg), 0o644))
	r.run(t, "add", "file.txt")
	r.run(t, "commit", "-m", msg)
}

// ctxAt returns a context after switching the process into the repo dir, so the
// git helpers (which shell out in the cwd) operate on this repo.
func (r *gitRepo) ctxAt(t *testing.T) context.Context {
	t.Helper()
	cwd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(r.dir))
	t.Cleanup(func() { _ = os.Chdir(cwd) })
	return t.Context()
}

func (r *gitRepo) run(t *testing.T, args ...string) {
	t.Helper()
	runGitIn(t, r.dir, args...)
}

func runGitIn(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git %v: %s", args, out)
}
