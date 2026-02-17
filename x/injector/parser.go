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
