package secrets

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
)

const xSecretPrefix = "x-secret"

func parseXSecretLabel(key, value string) (string, string, error) {
	if !strings.HasPrefix(key, xSecretPrefix+":") {
		return "", "", fmt.Errorf("label does not start with x-secret: %s", key)
	}
	name := strings.TrimPrefix(key, xSecretPrefix+":")
	if !strings.HasPrefix(value, "/") {
		return "", "", fmt.Errorf("%s is not an absolute path", value)
	}
	return name, filepath.ToSlash(value), nil
}

func SecretMapFromLabels(labels map[string]string) map[string]string {
	result := make(map[string]string)
	for k, v := range labels {
		if !strings.HasPrefix(k, xSecretPrefix+":") {
			continue
		}
		name, path, err := parseXSecretLabel(k, v)
		if err != nil {
			logrus.Warnf("parsing x-secret label: %v", err)
			continue
		}
		result[name] = path
	}
	return result
}
