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

package examples

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSecretExample(t *testing.T) {
	s := &secret{
		AccessToken:  "access_token",
		RefreshToken: "refresh_token",
	}
	data, err := s.Marshal()
	require.NoError(t, err)
	require.Equal(t, string(data), "access_token:refresh_token")

	anotherSecret := &secret{}
	require.NoError(t, anotherSecret.Unmarshal(data))
	require.EqualValues(t, s, anotherSecret)
}
