package project

import (
	"context"
	"errors"
	"os"
	"path/filepath"
)

type Project interface {
	String() string
	Name() string
	Dir() string
}

type project struct {
	value string
}

func (p project) String() string {
	return p.value
}

func (p project) Name() string {
	panic("implement me")
}

func (p project) Dir() string {
	return p.value
}

var ErrNotInGitRepo = errors.New("not in a git repo")

func CurrentGitProject() (Project, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	root, err := findGitProjectRoot(cwd)
	if err != nil {
		return nil, err
	}
	return project{value: root}, nil
}

func findGitProjectRoot(dir string) (string, error) {
	for {
		gitPath := filepath.Join(dir, ".git")
		if i, err := os.Stat(gitPath); err == nil && i.IsDir() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", ErrNotInGitRepo
}

type projectKey struct{}

// WithProject returns a new context with the provided project.
func WithProject(ctx context.Context, project Project) context.Context {
	return context.WithValue(ctx, projectKey{}, project)
}

// FromContext retrieves the current project from the context. If no project is
// available, ErrNotInGitRepo is returned.
func FromContext(ctx context.Context) (Project, error) {
	if logger, ok := ctx.Value(projectKey{}).(Project); ok {
		return logger, nil
	}
	return nil, ErrNotInGitRepo
}
