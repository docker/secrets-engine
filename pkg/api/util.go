package api

import (
	"errors"
	"fmt"
	"strings"
)

func ParsePluginName(name string) (string, string, error) {
	split := strings.SplitN(name, "-", 2)
	if len(split) < 2 {
		return "", "", fmt.Errorf("invalid plugin name %q, <[0-9][0-9]>-<pluginname> expected", name)
	}

	if err := CheckPluginIndex(split[0]); err != nil {
		return "", "", err
	}

	return split[0], split[1], nil
}

type ErrInvalidPluginIndex struct {
	Actual string
	Msg    string
}

func (e ErrInvalidPluginIndex) Error() string {
	return fmt.Sprintf("invalid plugin index %s: %s", e.Actual, e.Msg)
}

func (e ErrInvalidPluginIndex) Is(target error) bool {
	var t *ErrInvalidPluginIndex
	ok := errors.As(target, &t)
	if !ok {
		return false
	}
	return e.Actual == t.Actual && e.Msg == t.Msg
}

func CheckPluginIndex(idx string) error {
	if len(idx) != 2 {
		return &ErrInvalidPluginIndex{Actual: idx, Msg: "must be two digits"}
	}
	if !('0' <= idx[0] && idx[0] <= '9') || !('0' <= idx[1] && idx[1] <= '9') {
		return &ErrInvalidPluginIndex{Actual: idx, Msg: "pattern does not match [0-9][0-9]"}
	}
	return nil
}
