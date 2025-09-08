package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/mod/semver"
)

type futureVersions struct {
	patch string
	minor string
	major string
}

func newFutureVersions(latest string) (*futureVersions, error) {
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
	return &futureVersions{
		major: fmt.Sprintf("v%d.0.0", major+1),
		minor: fmt.Sprintf("v%d.%d.0", major, minor+1),
		patch: fmt.Sprintf("v%d.%d.%d", major, minor, patch+1),
	}, nil
}

func cutVersionExtra(cv string) (string, string) {
	if i := strings.IndexByte(cv, '-'); i >= 0 {
		return cv[:i], cv[i:]
	}
	if i := strings.IndexByte(cv, '+'); i >= 0 {
		return cv[:i], cv[i:]
	}
	return cv, ""
}
