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

package helper

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_bumpIterative(t *testing.T) {
	t.Parallel()
	t.Run("bump module with cascading dependencies", func(t *testing.T) {
		repo := newMockRepoData()
		m := &mockFS{}
		assert.NoError(t, BumpIterative("x", Major, repo, m))
		assert.ElementsMatch(t, m.tagsCreated, []string{
			"x/v1.0.0-do.not.use",
			"plugin/v0.1.1",
			"client/v1.0.3",
			"runtime/v0.2.4",
		})
		pluginIdx := getIndex(t, "plugin", m.tagsCreated)
		clientIdx := getIndex(t, "client", m.tagsCreated)
		assert.ElementsMatch(t, m.bumps, []bump{
			{"runtime/go.mod", "x", "v1.0.0-do.not.use"},
			{"runtime/go.mod", "plugin", "v0.1.1"},
			{"runtime/go.mod", "client", "v1.0.3"},
			{"client/go.mod", "x", "v1.0.0-do.not.use"},
			{"plugin/go.mod", "x", "v1.0.0-do.not.use"},
		})
		require.Equal(t, 3, len(m.commits))
		assert.Equal(t, "chore: bump x/v1.0.0-do.not.use", m.commits[0])
		assert.Equal(t, "chore: bump plugin/v0.1.1", m.commits[pluginIdx])
		assert.Equal(t, "chore: bump client/v1.0.3", m.commits[clientIdx])
	})
	t.Run("bump module with direct dependencies", func(t *testing.T) {
		repo := newMockRepoData()
		m := &mockFS{}
		assert.NoError(t, BumpIterative("plugin", Patch, repo, m))
		assert.ElementsMatch(t, m.tagsCreated, []string{
			"plugin/v0.1.1",
			"runtime/v0.2.4",
		})
		assert.ElementsMatch(t, m.bumps, []bump{
			{"runtime/go.mod", "plugin", "v0.1.1"},
		})
		require.Equal(t, 1, len(m.commits))
		assert.Equal(t, "chore: bump plugin/v0.1.1", m.commits[0])
	})
	t.Run("bump module without dependencies", func(t *testing.T) {
		repo := newMockRepoData()
		m := &mockFS{}
		assert.NoError(t, BumpIterative("runtime", Patch, repo, m))
		assert.ElementsMatch(t, m.tagsCreated, []string{
			"runtime/v0.2.4",
		})
		assert.Empty(t, m.bumps)
		assert.Empty(t, m.commits)
	})
}

func getIndex(t *testing.T, prefix string, items []string) int {
	for i, item := range items {
		if strings.HasPrefix(item, prefix) {
			return i
		}
	}
	t.Fatalf("no items found for prefix %s", prefix)
	return -1
}

func Test_bumpModule(t *testing.T) {
	t.Parallel()
	t.Run("bump module with version metadata and dependencies", func(t *testing.T) {
		repo := newMockRepoData()
		m := &mockFS{}
		assert.NoError(t, BumpModule("x", Patch, repo["x"], m))
		assert.ElementsMatch(t, m.tagsCreated, []string{"x/v0.0.4-do.not.use"})
		assert.ElementsMatch(t, m.bumps, []bump{
			{"runtime/go.mod", "x", "v0.0.4-do.not.use"},
			{"client/go.mod", "x", "v0.0.4-do.not.use"},
			{"plugin/go.mod", "x", "v0.0.4-do.not.use"},
		})
		assert.ElementsMatch(t, m.commits, []string{"chore: bump x/v0.0.4-do.not.use"})
		original := newMockRepoData()
		assert.Equal(t, original, repo, "no side effects in BumpModule")
	})
	t.Run("bump module without version metadata and no dependencies", func(t *testing.T) {
		repo := newMockRepoData()
		m := &mockFS{}
		assert.NoError(t, BumpModule("runtime", Patch, repo["runtime"], m))
		assert.ElementsMatch(t, m.tagsCreated, []string{"runtime/v0.2.4"})
		assert.ElementsMatch(t, m.bumps, []bump{})
	})
}

func newMockRepoData() RepoData {
	modules := RepoData{}
	modules.AddMod("x", Version{Current: "v0.0.3-do.not.use", KeepExtra: true}, []string{})
	modules.AddMod("plugin", Version{Current: "v0.1.0"}, []string{"x"})
	modules.AddMod("client", Version{Current: "v1.0.2"}, []string{"x"})
	modules.AddMod("runtime", Version{Current: "v0.2.3"}, []string{"client", "plugin", "x"})
	return modules
}

type mockFS struct {
	tagsCreated []string
	bumps       []bump
	commits     []string
}

func (m *mockFS) GitCommit(commit string) error {
	m.commits = append(m.commits, commit)
	return nil
}

type bump struct {
	filename string
	dep      string
	version  string
}

func (m *mockFS) GitTag(tag string) error {
	m.tagsCreated = append(m.tagsCreated, tag)
	return nil
}

func (m *mockFS) BumpModInFile(filename, dep, version string) (bool, error) {
	m.bumps = append(m.bumps, bump{filename, dep, version})
	return true, nil
}

func Test_cutVersionExtra(t *testing.T) {
	t.Parallel()
	tests := []struct {
		versionBefore string
		versionAfter  string
		metadataAfter string
	}{
		{
			versionBefore: "v0.1.0",
			versionAfter:  "v0.1.0",
		},
		{
			versionBefore: "v0.1.0-pre+meta",
			versionAfter:  "v0.1.0",
			metadataAfter: "-pre+meta",
		},
		{
			versionBefore: "v0.1.0+meta",
			versionAfter:  "v0.1.0",
			metadataAfter: "+meta",
		},
	}
	for _, test := range tests {
		t.Run(test.versionBefore, func(t *testing.T) {
			v, extra := CutVersionExtra(test.versionBefore)
			assert.Equal(t, test.versionAfter, v)
			assert.Equal(t, test.metadataAfter, extra)
		})
	}
}

func Test_futureVersion(t *testing.T) {
	t.Parallel()
	t.Run("patch/minor/major", func(t *testing.T) {
		v := Version{Current: "v1.1.1-pre+meta"}
		patch, err := v.GetNextVersion(Patch)
		assert.NoError(t, err)
		assert.Equal(t, "v1.1.2", patch)
		minor, err := v.GetNextVersion(Minor)
		assert.NoError(t, err)
		assert.Equal(t, "v1.2.0", minor)
		major, err := v.GetNextVersion(Major)
		assert.NoError(t, err)
		assert.Equal(t, "v2.0.0", major)
	})
	t.Run("with metadata", func(t *testing.T) {
		v := Version{Current: "v1.1.1-pre+meta", KeepExtra: true}
		patch, err := v.GetNextVersion(Patch)
		assert.NoError(t, err)
		assert.Equal(t, "v1.1.2-pre+meta", patch)
	})
}
