package helper

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/pflag"
	"golang.org/x/mod/semver"
)

type Level string

const (
	Patch Level = "patch"
	Minor Level = "minor"
	Major Level = "major"
)

var Levels = []Level{Patch, Minor, Major}

var _ pflag.Value = (*Level)(nil)

func (e *Level) String() string {
	return string(*e)
}

func (e *Level) Set(v string) error {
	actual := Level(v)
	if !slices.Contains(Levels, actual) {
		return fmt.Errorf("must be one of %s", AllowedLevels())
	}
	*e = actual
	return nil
}

func (e *Level) Type() string {
	return "level"
}

func AllowedLevels() string {
	var quoted []string
	for _, v := range Levels {
		quoted = append(quoted, "\""+string(v)+"\"")
	}
	return strings.Join(quoted, ", ")
}

func BumpIterative(mod string, level Level, repo RepoData, i FS) error {
	data, ok := repo[mod]
	if !ok {
		return fmt.Errorf("module %s not found", mod)
	}
	if err := BumpModule(mod, level, data, i); err != nil {
		return err
	}
	queue := data.downstreams

	// reduce the repo data to only the downstream modules of 'mod'
	for k := range repo {
		if _, ok := queue[k]; ok {
			continue
		}
		repo.RemoveModule(k)
	}

	for len(queue) > 0 {
		var nextMod string
		for item := range queue {
			if repo.GetDependencyCount(item) == 0 {
				nextMod = item
				break
			}
		}
		if nextMod == "" {
			return fmt.Errorf("could not determine next module")
		}
		data, ok := repo[nextMod]
		if !ok {
			return fmt.Errorf("module %s not found", mod)
		}
		// We always propagate as patch release. The alternative is to not propagate at all and manually
		// re-run the release automation with the desired type of version bump on the specific sub module.
		if err := BumpModule(nextMod, Patch, data, i); err != nil {
			return err
		}
		repo.RemoveModule(nextMod)
		delete(queue, nextMod)
	}
	return nil
}

type FS interface {
	GitTag(tag string) error
	GitCommit(msg string) error
	BumpModInFile(path, module, version string) (bool, error)
}

func BumpModule(mod string, level Level, data ModData, i FS) error {
	release := data.getByLevel(level)

	tag := mod + "/" + release
	if err := i.GitTag(tag); err != nil {
		return err
	}
	needsCommit := false
	for dep := range data.downstreams {
		modified, err := i.BumpModInFile(filepath.Join(dep, "go.mod"), mod, release)
		if err != nil {
			return err
		}
		if modified {
			needsCommit = true
		}
	}
	if !needsCommit {
		return nil
	}
	return i.GitCommit("chore: bump " + tag)
}

type RepoData map[string]ModData

func (d RepoData) AddMod(mod string, data FutureVersions, deps []string) {
	d.addVersionData(mod, data)
	d.addDeps(mod, deps)
}

func (d RepoData) addVersionData(mod string, data FutureVersions) {
	before := d.getOrInit(mod)
	before.FutureVersions = data
	d[mod] = before
}

func (d RepoData) addDeps(mod string, deps []string) {
	dependencies := map[string]struct{}{}
	for _, dep := range deps {
		dependencies[dep] = struct{}{}
		d.addDownstreamDep(mod, dep)
	}
	before := d.getOrInit(mod)
	before.dependencies = dependencies
	d[mod] = before
}

func (d RepoData) addDownstreamDep(mod, dep string) {
	before := d.getOrInit(dep)
	before.downstreams[mod] = struct{}{}
	d[dep] = before
}

func (d RepoData) getOrInit(mod string) ModData {
	result, ok := d[mod]
	if !ok {
		return ModData{downstreams: map[string]struct{}{}}
	}
	return result
}

func (d RepoData) GetDependencyCount(mod string) int {
	data, ok := d[mod]
	if !ok {
		return 0
	}
	return len(data.dependencies)
}

func (d RepoData) RemoveModule(mod string) {
	delete(d, mod)
	for _, v := range d {
		delete(v.dependencies, mod)
	}
}

type ModData struct {
	downstreams  map[string]struct{}
	dependencies map[string]struct{}
	FutureVersions
}

type FutureVersions struct {
	patch string
	minor string
	major string
}

func (f *FutureVersions) getByLevel(level Level) string {
	if level == Major {
		return f.major
	}
	if level == Minor {
		return f.minor
	}
	return f.patch
}

func WithExtra(value string) Opt {
	return func(v *FutureVersions) {
		v.patch += value
		v.minor += value
		v.major += value
	}
}

type Opt func(f *FutureVersions)

func NewFutureVersions(latest string, opts ...Opt) (*FutureVersions, error) {
	v := semver.Canonical(latest)
	if v == "" {
		return nil, fmt.Errorf("not a canonical version: %s", latest)
	}
	parts := strings.SplitN(strings.TrimPrefix(v, "v"), ".", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("unexpected semver parts: %q", v)
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	patch, err3 := strconv.Atoi(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, fmt.Errorf("failed to parse semver numbers %q: %s", v, errors.Join(err1, err2, err3))
	}
	result := &FutureVersions{
		major: fmt.Sprintf("v%d.0.0", major+1),
		minor: fmt.Sprintf("v%d.%d.0", major, minor+1),
		patch: fmt.Sprintf("v%d.%d.%d", major, minor, patch+1),
	}
	for _, opt := range opts {
		opt(result)
	}
	return result, nil
}

func CutVersionExtra(cv string) (string, string) {
	if i := strings.IndexByte(cv, '-'); i >= 0 {
		return cv[:i], cv[i:]
	}
	if i := strings.IndexByte(cv, '+'); i >= 0 {
		return cv[:i], cv[i:]
	}
	return cv, ""
}
