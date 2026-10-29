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

package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	xsemver "golang.org/x/mod/semver"
)

var semverVectors = []string{
	"",
	"v",
	"1.0.0",
	"v1",
	"v1.0",
	"v1.0.0",
	"v1.2.3",
	"v10.20.30",
	"v01",
	"v1.02",
	"v1.2.03",
	"v1.2.3.4",
	"v1.",
	"v1..2",
	"v1.2.",
	"v0",
	"v0.0.0",
	"v1-pre",
	"v1.2-pre",
	"v1+meta",
	"v1.2+meta",
	"v1.2.3-",
	"v1.2.3+",
	"v1.2.3-alpha",
	"v1.2.3-alpha.1",
	"v1.2.3-alpha.beta",
	"v1.2.3-alpha.01",
	"v1.2.3-0",
	"v1.2.3-00",
	"v1.2.3-0a",
	"v1.2.3-01a",
	"v1.2.3-1",
	"v1.2.3-2",
	"v1.2.3-10",
	"v1.2.3-a-b",
	"v1.2.3--",
	"v1.2.3-alpha..1",
	"v1.2.3-alpha.",
	"v1.2.3-beta",
	"v1.2.3-beta.2",
	"v1.2.3-beta.11",
	"v1.2.3-rc.1",
	"v1.2.3+build",
	"v1.2.3+build.01",
	"v1.2.3+build+x",
	"v1.2.3-rc.1+build.5",
	"v1.2.3-rc_1",
	"v1.2.3+b_1",
	"v2.0.0",
	"v2.0.0-0.3.7",
	"v1.0.0-x.7.z.92",
	"V1.0.0",
	"v1.0.0 ",
	"v-1",
	"v1.-1.0",
}

func TestSemverMatchesXMod(t *testing.T) {
	t.Parallel()
	for _, v := range semverVectors {
		_, ok := parseSemver(v)
		assert.Equal(t, xsemver.IsValid(v), ok, "valid(%q)", v)
	}
	for _, a := range semverVectors {
		for _, b := range semverVectors {
			assert.Equal(t, xsemver.Compare(a, b), compareSemver(a, b), "compare(%q, %q)", a, b)
		}
	}
}

func FuzzSemverMatchesXMod(f *testing.F) {
	for _, v := range semverVectors {
		f.Add(v, "v1.2.3-rc.1")
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		_, okA := parseSemver(a)
		assert.Equal(t, xsemver.IsValid(a), okA, "valid(%q)", a)
		assert.Equal(t, xsemver.Compare(a, b), compareSemver(a, b), "compare(%q, %q)", a, b)
	})
}
