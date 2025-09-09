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
		repo, err := newMockRepoData()
		require.NoError(t, err)
		m := &mockFS{}
		assert.NoError(t, BumpIterative("x", Major, repo, m))
		assert.ElementsMatch(t, m.tagsCreated, []string{
			"x/v1.0.0-do.not.use",
			"plugin/v0.1.1",
			"client/v1.0.3",
			"engine/v0.2.4",
		})
		pluginIdx := getIndex(t, "plugin", m.tagsCreated)
		clientIdx := getIndex(t, "client", m.tagsCreated)
		assert.ElementsMatch(t, m.bumps, []bump{
			{"engine/go.mod", "x", "v1.0.0-do.not.use"},
			{"engine/go.mod", "plugin", "v0.1.1"},
			{"engine/go.mod", "client", "v1.0.3"},
			{"client/go.mod", "x", "v1.0.0-do.not.use"},
			{"plugin/go.mod", "x", "v1.0.0-do.not.use"},
		})
		require.Equal(t, 4, len(m.commits))
		assert.Equal(t, "chore: bump x/v1.0.0-do.not.use", m.commits[0])
		assert.Equal(t, "chore: bump plugin/v0.1.1", m.commits[pluginIdx])
		assert.Equal(t, "chore: bump client/v1.0.3", m.commits[clientIdx])
		assert.Equal(t, "chore: bump engine/v0.2.4", m.commits[3])
		assert.Equal(t, 4, m.makeModCalled)
	})
	t.Run("bump module with direct dependencies", func(t *testing.T) {
		repo, err := newMockRepoData()
		require.NoError(t, err)
		m := &mockFS{}
		assert.NoError(t, BumpIterative("plugin", Patch, repo, m))
		assert.ElementsMatch(t, m.tagsCreated, []string{
			"plugin/v0.1.1",
			"engine/v0.2.4",
		})
		assert.ElementsMatch(t, m.bumps, []bump{
			{"engine/go.mod", "plugin", "v0.1.1"},
		})
		require.Equal(t, 2, len(m.commits))
		assert.Equal(t, "chore: bump plugin/v0.1.1", m.commits[0])
		assert.Equal(t, "chore: bump engine/v0.2.4", m.commits[1])
		assert.Equal(t, 2, m.makeModCalled)
	})
	t.Run("bump module without dependencies", func(t *testing.T) {
		repo, err := newMockRepoData()
		require.NoError(t, err)
		m := &mockFS{}
		assert.NoError(t, BumpIterative("engine", Patch, repo, m))
		assert.ElementsMatch(t, m.tagsCreated, []string{
			"engine/v0.2.4",
		})
		assert.Empty(t, m.bumps)
		require.Equal(t, 1, len(m.commits))
		assert.Equal(t, "chore: bump engine/v0.2.4", m.commits[0])
		assert.Equal(t, 1, m.makeModCalled)
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
		repo, err := newMockRepoData()
		require.NoError(t, err)
		m := &mockFS{}
		assert.NoError(t, BumpModule("x", Patch, repo["x"], m))
		assert.ElementsMatch(t, m.tagsCreated, []string{"x/v0.0.4-do.not.use"})
		assert.ElementsMatch(t, m.bumps, []bump{
			{"engine/go.mod", "x", "v0.0.4-do.not.use"},
			{"client/go.mod", "x", "v0.0.4-do.not.use"},
			{"plugin/go.mod", "x", "v0.0.4-do.not.use"},
		})
		assert.ElementsMatch(t, m.commits, []string{"chore: bump x/v0.0.4-do.not.use"})
		assert.Equal(t, 1, m.makeModCalled)
		original, err := newMockRepoData()
		require.NoError(t, err)
		assert.Equal(t, original, repo, "no side effects in BumpModule")
	})
	t.Run("bump module without version metadata and no dependencies", func(t *testing.T) {
		repo, err := newMockRepoData()
		require.NoError(t, err)
		m := &mockFS{}
		assert.NoError(t, BumpModule("engine", Patch, repo["engine"], m))
		assert.ElementsMatch(t, m.tagsCreated, []string{"engine/v0.2.4"})
		assert.ElementsMatch(t, m.bumps, []bump{})
	})
}

func newMockRepoData() (RepoData, error) {
	modules := RepoData{}
	xVersion, extra := CutVersionExtra("v0.0.3-do.not.use")
	x, err := NewFutureVersions(xVersion, WithExtra(extra))
	if err != nil {
		return nil, err
	}
	modules.AddMod("x", *x, []string{})
	plugin, err := NewFutureVersions("v0.1.0")
	if err != nil {
		return nil, err
	}
	modules.AddMod("plugin", *plugin, []string{"x"})
	client, err := NewFutureVersions("v1.0.2")
	if err != nil {
		return nil, err
	}
	modules.AddMod("client", *client, []string{"x"})
	engine, err := NewFutureVersions("v0.2.3")
	if err != nil {
		return nil, err
	}
	modules.AddMod("engine", *engine, []string{"client", "plugin", "x"})
	return modules, nil
}

type mockFS struct {
	tagsCreated   []string
	bumps         []bump
	commits       []string
	makeModCalled int
}

func (m *mockFS) BeforeCommit() error {
	m.makeModCalled++
	return nil
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

func (m *mockFS) BumpModInFile(filename, dep, version string) error {
	m.bumps = append(m.bumps, bump{filename, dep, version})
	return nil
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
	t.Run("non canonical version", func(t *testing.T) {
		_, err := NewFutureVersions("v0.0.0.1")
		assert.Error(t, err)
	})
	tests := []struct {
		current string
		result  *FutureVersions
	}{
		{
			current: "v0.0.1",
			result: &FutureVersions{
				major: "v1.0.0",
				minor: "v0.1.0",
				patch: "v0.0.2",
			},
		},
		{
			current: "v0.1.1",
			result: &FutureVersions{
				major: "v1.0.0",
				minor: "v0.2.0",
				patch: "v0.1.2",
			},
		},
		{
			current: "v1.1.1",
			result: &FutureVersions{
				major: "v2.0.0",
				minor: "v1.2.0",
				patch: "v1.1.2",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.current, func(t *testing.T) {
			d, err := NewFutureVersions(test.current)
			require.NoError(t, err)
			assert.Equal(t, *test.result, *d)
		})
	}
}
