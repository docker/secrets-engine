package helper

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/mod/semver"
)

type ReleaseLevel int

const (
	Patch ReleaseLevel = iota
	Minor
	Major
)

type FS interface {
	GitTag(tag string) error
	GitCommit(msg string) error
	BumpModInFile(path, module, version string) error
	BeforeCommit() error
}

func BumpModule(mod string, level ReleaseLevel, data ModData, i FS) error {
	release := data.getByLevel(level)

	tag := mod + "/" + release
	if err := i.GitTag(tag); err != nil {
		return err
	}
	for dep := range data.downstreams {
		if err := i.BumpModInFile(filepath.Join(dep, "go.mod"), mod, release); err != nil {
			return err
		}
	}
	if err := i.BeforeCommit(); err != nil {
		return err
	}
	return i.GitCommit("chore: bump " + tag)
}

type RepoData map[string]ModData

func (d *RepoData) AddMod(mod string, data FutureVersions, deps []string) {
	d.addVersionData(mod, data)
	d.addDeps(mod, deps)
}

func (d *RepoData) addVersionData(mod string, data FutureVersions) {
	before := d.getOrInit(mod)
	before.FutureVersions = data
	(*d)[mod] = before
}

func (d *RepoData) addDeps(mod string, deps []string) {
	dependencies := map[string]struct{}{}
	for _, dep := range deps {
		dependencies[dep] = struct{}{}
		d.addDownstreamDep(mod, dep)
	}
	before := d.getOrInit(mod)
	before.dependencies = dependencies
	(*d)[mod] = before
}

func (d *RepoData) addDownstreamDep(mod, dep string) {
	before := d.getOrInit(dep)
	before.downstreams[mod] = struct{}{}
	(*d)[dep] = before
}

func (d *RepoData) getOrInit(mod string) ModData {
	result, ok := (*d)[mod]
	if !ok {
		return ModData{downstreams: map[string]struct{}{}}
	}
	return result
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

func (f *FutureVersions) getByLevel(level ReleaseLevel) string {
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
