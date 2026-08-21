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

package dockerhub_test

import (
	"context"
	"encoding/json"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/client"
	"github.com/docker/secrets-engine/client/dockerhub"
	"github.com/docker/secrets-engine/x/secrets"
	"github.com/docker/secrets-engine/x/testhelper"
)

const sessionWire = `{
	"access_token": "token-alice",
	"claims": {
		"iss": "https://auth.docker.io",
		"sub": "user-uuid-1",
		"aud": ["audience.docker.io"],
		"exp": 1755500000,
		"nbf": 1755400000,
		"iat": 1755400000,
		"jti": "jwt-id-1",
		"scope": "read write",
		"app_name": "desktop",
		"uuid": "user-uuid-1",
		"source": "docker_pat|1",
		"session_id": "session-1",
		"email": "alice@example.com",
		"username": "alice"
	}
}`

const profileWire = `{
	"user_id": "docker/auth/hub/alice",
	"original_sign_in_app": "desktop",
	"username": "alice",
	"email": "alice@example.com",
	"sign_in_date": "2026-08-01T10:00:00Z"
}`

type fakeEngine struct {
	testhelper.MockResolver
	err error
}

func (f fakeEngine) GetSecrets(ctx context.Context, pattern secrets.Pattern) ([]secrets.Envelope, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.MockResolver.GetSecrets(ctx, pattern)
}

func serving(store map[string]string) fakeEngine {
	resolved := make(map[secrets.ID]string, len(store))
	for id, value := range store {
		resolved[secrets.MustParseID(id)] = value
	}
	return fakeEngine{MockResolver: testhelper.MockResolver{Store: resolved}}
}

type nilIDEngine map[string]string

func (e nilIDEngine) GetSecrets(_ context.Context, pattern secrets.Pattern) ([]secrets.Envelope, error) {
	var envelopes []secrets.Envelope
	for _, id := range slices.Sorted(maps.Keys(e)) {
		if pattern.Match(secrets.MustParseID(id)) {
			envelopes = append(envelopes, secrets.Envelope{Value: []byte(e[id])})
		}
	}
	if len(envelopes) == 0 {
		return nil, secrets.ErrNotFound
	}
	return envelopes, nil
}

type staticEngine struct {
	envelopes []secrets.Envelope
}

func (s staticEngine) GetSecrets(context.Context, secrets.Pattern) ([]secrets.Envelope, error) {
	return s.envelopes, nil
}

func envelope(value string) secrets.Envelope {
	return secrets.Envelope{Value: []byte(value), Provider: "docker-auth", Version: "0.0.1"}
}

func hub(t *testing.T, engine secrets.Resolver, opts ...dockerhub.Option) dockerhub.ClientAuth {
	t.Helper()
	return dockerhub.New(engine, opts...)
}

func TestNew(t *testing.T) {
	t.Parallel()
	require.Panics(t, func() { dockerhub.New(nil) })
}

func TestGetSession(t *testing.T) {
	t.Parallel()
	t.Run("decodes the wire format", func(t *testing.T) {
		engine := serving(map[string]string{
			"docker/auth/hub/alice": sessionWire,
		})
		session, err := hub(t, engine).GetSession(t.Context(), "alice")
		require.NoError(t, err)
		assert.Equal(t, "token-alice", session.AccessToken)
		assert.Equal(t, "https://auth.docker.io", session.Claims.Issuer)
		assert.Equal(t, "user-uuid-1", session.Claims.Subject)
		assert.Equal(t, dockerhub.Audience{"audience.docker.io"}, session.Claims.Audience)
		require.NotNil(t, session.Claims.ExpiresAt)
		assert.Equal(t, int64(1755500000), session.Claims.ExpiresAt.Unix())
		require.NotNil(t, session.Claims.NotBefore)
		assert.Equal(t, int64(1755400000), session.Claims.NotBefore.Unix())
		require.NotNil(t, session.Claims.IssuedAt)
		assert.Equal(t, int64(1755400000), session.Claims.IssuedAt.Unix())
		assert.Equal(t, "jwt-id-1", session.Claims.ID)
		assert.Equal(t, "read write", session.Claims.Scope)
		assert.Equal(t, "desktop", session.Claims.AppName)
		assert.Equal(t, "user-uuid-1", session.Claims.UUID)
		assert.Equal(t, "docker_pat|1", session.Claims.Source)
		assert.Equal(t, "session-1", session.Claims.SessionID)
		assert.Equal(t, "alice@example.com", session.Claims.Email)
		assert.Equal(t, "alice", session.Claims.Username)
	})
	t.Run("audience as single string", func(t *testing.T) {
		engine := serving(map[string]string{
			"docker/auth/hub/alice": `{"access_token":"tok","claims":{"aud":"audience.docker.io","app_name":"cli","uuid":"u","source":"s","session_id":"sid","email":"e","username":"alice"}}`,
		})
		session, err := hub(t, engine).GetSession(t.Context(), "alice")
		require.NoError(t, err)
		assert.Equal(t, dockerhub.Audience{"audience.docker.io"}, session.Claims.Audience)
	})
	t.Run("fractional expiry seconds", func(t *testing.T) {
		engine := serving(map[string]string{
			"docker/auth/hub/alice": `{"access_token":"tok","claims":{"exp":1755500000.5,"app_name":"cli","uuid":"u","source":"s","session_id":"sid","email":"e","username":"alice"}}`,
		})
		session, err := hub(t, engine).GetSession(t.Context(), "alice")
		require.NoError(t, err)
		require.NotNil(t, session.Claims.ExpiresAt)
		assert.Equal(t, int64(1755500000), session.Claims.ExpiresAt.Unix())
		assert.Equal(t, 500000000, session.Claims.ExpiresAt.Nanosecond())
	})
	t.Run("payload without claims", func(t *testing.T) {
		engine := serving(map[string]string{
			"docker/auth/hub/alice": `{"access_token":"tok"}`,
		})
		session, err := hub(t, engine).GetSession(t.Context(), "alice")
		require.NoError(t, err)
		assert.Equal(t, "tok", session.AccessToken)
		assert.Equal(t, dockerhub.Claims{}, session.Claims)
	})
	t.Run("skips undecodable envelopes", func(t *testing.T) {
		engine := staticEngine{envelopes: []secrets.Envelope{
			envelope(`not json`), envelope(`{"access_token":""}`), envelope(`{"access_token":"tok"}`),
		}}
		session, err := hub(t, engine).GetSession(t.Context(), "alice")
		require.NoError(t, err)
		assert.Equal(t, "tok", session.AccessToken)
	})
	t.Run("all envelopes undecodable", func(t *testing.T) {
		engine := staticEngine{envelopes: []secrets.Envelope{
			envelope(`not json`), envelope(`{"access_token":""}`),
		}}
		_, err := hub(t, engine).GetSession(t.Context(), "alice")
		require.ErrorContains(t, err, "decode user session")
		require.ErrorContains(t, err, "no access token in payload")
	})
	t.Run("no stored credential", func(t *testing.T) {
		_, err := hub(t, serving(nil)).GetSession(t.Context(), "alice")
		require.ErrorIs(t, err, dockerhub.ErrNoSession)
	})
	t.Run("engine reports not found", func(t *testing.T) {
		_, err := hub(t, fakeEngine{err: client.ErrSecretNotFound}).GetSession(t.Context(), "alice")
		require.ErrorIs(t, err, dockerhub.ErrNoSession)
	})
	t.Run("provider returns no envelopes without error", func(t *testing.T) {
		_, err := hub(t, staticEngine{}).GetSession(t.Context(), "alice")
		require.ErrorIs(t, err, dockerhub.ErrNoSession)
	})
	t.Run("rejects wildcard usernames", func(t *testing.T) {
		_, err := hub(t, serving(nil)).GetSession(t.Context(), "*")
		require.ErrorContains(t, err, "invalid username")
		_, err = hub(t, serving(nil)).GetSession(t.Context(), "")
		require.ErrorContains(t, err, "invalid username")
	})
	t.Run("rejects multi-component usernames", func(t *testing.T) {
		_, err := hub(t, serving(map[string]string{
			"docker/auth/hub/alice/extra": sessionWire,
		})).GetSession(t.Context(), "alice/extra")
		require.ErrorContains(t, err, "must not contain '/'")
	})
	t.Run("engine unavailable", func(t *testing.T) {
		_, err := hub(t, fakeEngine{err: client.ErrSecretsEngineNotAvailable}).GetSession(t.Context(), "alice")
		require.ErrorIs(t, err, client.ErrSecretsEngineNotAvailable)
	})
}

func TestGetDefaultProfile(t *testing.T) {
	t.Parallel()
	t.Run("returns the default profile", func(t *testing.T) {
		engine := serving(map[string]string{
			"docker/auth/metadata/hub/default": profileWire,
		})
		profile, err := hub(t, engine).GetDefaultProfile(t.Context())
		require.NoError(t, err)
		assert.Equal(t, dockerhub.Profile{
			UserID:            "docker/auth/hub/alice",
			OriginalSignInApp: "desktop",
			Username:          "alice",
			Email:             "alice@example.com",
			SignInDate:        time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC),
		}, profile)
	})
	t.Run("no default profile", func(t *testing.T) {
		_, err := hub(t, serving(nil)).GetDefaultProfile(t.Context())
		require.ErrorIs(t, err, dockerhub.ErrNoDefaultProfile)
	})
	t.Run("engine reports not found", func(t *testing.T) {
		_, err := hub(t, fakeEngine{err: client.ErrSecretNotFound}).GetDefaultProfile(t.Context())
		require.ErrorIs(t, err, dockerhub.ErrNoDefaultProfile)
	})
	t.Run("provider returns no envelopes without error", func(t *testing.T) {
		_, err := hub(t, staticEngine{}).GetDefaultProfile(t.Context())
		require.ErrorIs(t, err, dockerhub.ErrNoDefaultProfile)
	})
	t.Run("profile without user id", func(t *testing.T) {
		engine := serving(map[string]string{
			"docker/auth/metadata/hub/default": `{"username":"alice"}`,
		})
		_, err := hub(t, engine).GetDefaultProfile(t.Context())
		require.ErrorContains(t, err, "decode profile metadata")
	})
}

func TestGetDefaultSession(t *testing.T) {
	t.Parallel()
	t.Run("resolves the default profile to its session", func(t *testing.T) {
		engine := serving(map[string]string{
			"docker/auth/metadata/hub/default": profileWire,
			"docker/auth/hub/alice":            sessionWire,
		})
		session, err := hub(t, engine).GetDefaultSession(t.Context())
		require.NoError(t, err)
		assert.Equal(t, "token-alice", session.AccessToken)
		assert.Equal(t, "alice", session.Claims.Username)
	})
	t.Run("no default profile", func(t *testing.T) {
		_, err := hub(t, serving(nil)).GetDefaultSession(t.Context())
		require.ErrorIs(t, err, dockerhub.ErrNoDefaultProfile)
		require.ErrorIs(t, err, dockerhub.ErrNoSession)
	})
	t.Run("profile points at a missing credential", func(t *testing.T) {
		engine := serving(map[string]string{
			"docker/auth/metadata/hub/default": profileWire,
		})
		_, err := hub(t, engine).GetDefaultSession(t.Context())
		require.ErrorIs(t, err, dockerhub.ErrNoSession)
	})
	t.Run("rejects a wildcard user id", func(t *testing.T) {
		engine := serving(map[string]string{
			"docker/auth/metadata/hub/default": `{"user_id":"docker/auth/hub/*"}`,
			"docker/auth/hub/alice":            sessionWire,
		})
		_, err := hub(t, engine).GetDefaultSession(t.Context())
		require.ErrorContains(t, err, "default profile user id")
	})
	t.Run("rejects a fan-out wildcard user id", func(t *testing.T) {
		engine := serving(map[string]string{
			"docker/auth/metadata/hub/default": `{"user_id":"docker/**"}`,
			"docker/auth/hub/alice":            sessionWire,
		})
		_, err := hub(t, engine).GetDefaultSession(t.Context())
		require.ErrorContains(t, err, "default profile user id")
	})
	t.Run("rejects a nested user id", func(t *testing.T) {
		engine := serving(map[string]string{
			"docker/auth/metadata/hub/default": `{"user_id":"docker/auth/hub/alice/extra"}`,
			"docker/auth/hub/alice/extra":      sessionWire,
		})
		_, err := hub(t, engine).GetDefaultSession(t.Context())
		require.ErrorContains(t, err, "not an account entry in the docker/auth/hub/** realm")
	})
	t.Run("rejects a user id outside the accounts realm", func(t *testing.T) {
		engine := serving(map[string]string{
			"docker/auth/metadata/hub/default": `{"user_id":"docker/mcp/oauth/github"}`,
			"docker/mcp/oauth/github":          sessionWire,
		})
		_, err := hub(t, engine).GetDefaultSession(t.Context())
		require.ErrorContains(t, err, "not an account entry in the docker/auth/hub/** realm")
	})
	t.Run("rejects a staging user id on the production realm", func(t *testing.T) {
		engine := serving(map[string]string{
			"docker/auth/metadata/hub/default": `{"user_id":"docker/auth/hub-staging/alice"}`,
			"docker/auth/hub-staging/alice":    sessionWire,
		})
		_, err := hub(t, engine).GetDefaultSession(t.Context())
		require.ErrorContains(t, err, "not an account entry in the docker/auth/hub/** realm")
	})
	t.Run("rejects a production user id on the staging realm", func(t *testing.T) {
		engine := serving(map[string]string{
			"docker/auth/metadata/hub-staging/default": profileWire,
			"docker/auth/hub/alice":                    sessionWire,
		})
		_, err := hub(t, engine, dockerhub.Staging()).GetDefaultSession(t.Context())
		require.ErrorContains(t, err, "not an account entry in the docker/auth/hub-staging/** realm")
	})
}

func TestListProfiles(t *testing.T) {
	t.Parallel()
	t.Run("lists accounts and skips the default entry", func(t *testing.T) {
		engine := serving(map[string]string{
			"docker/auth/metadata/hub/default": profileWire,
			"docker/auth/metadata/hub/alice":   profileWire,
			"docker/auth/metadata/hub/bob":     `{"user_id":"docker/auth/hub/bob","username":"bob"}`,
		})
		profiles, err := hub(t, engine).ListProfiles(t.Context())
		require.NoError(t, err)
		require.Len(t, profiles, 2)
		assert.Equal(t, "alice", profiles[0].Username)
		assert.Equal(t, "bob", profiles[1].Username)
	})
	t.Run("dedupes entries sharing a user id", func(t *testing.T) {
		engine := serving(map[string]string{
			"docker/auth/metadata/hub/alice": profileWire,
			"docker/auth/metadata/hub/alias": profileWire,
		})
		profiles, err := hub(t, engine).ListProfiles(t.Context())
		require.NoError(t, err)
		require.Len(t, profiles, 1)
		assert.Equal(t, "alice", profiles[0].Username)
	})
	t.Run("skips the default entry without envelope IDs", func(t *testing.T) {
		engine := nilIDEngine{
			"docker/auth/metadata/hub/default": profileWire,
			"docker/auth/metadata/hub/alice":   profileWire,
			"docker/auth/metadata/hub/bob":     `{"user_id":"docker/auth/hub/bob","username":"bob"}`,
		}
		profiles, err := hub(t, engine).ListProfiles(t.Context())
		require.NoError(t, err)
		require.Len(t, profiles, 2)
		assert.ElementsMatch(t, []string{"alice", "bob"}, []string{profiles[0].Username, profiles[1].Username})
	})
	t.Run("no accounts", func(t *testing.T) {
		profiles, err := hub(t, serving(nil)).ListProfiles(t.Context())
		require.NoError(t, err)
		assert.Empty(t, profiles)
	})
	t.Run("engine reports not found", func(t *testing.T) {
		profiles, err := hub(t, fakeEngine{err: client.ErrSecretNotFound}).ListProfiles(t.Context())
		require.NoError(t, err)
		assert.Empty(t, profiles)
	})
	t.Run("skips undecodable entries", func(t *testing.T) {
		engine := serving(map[string]string{
			"docker/auth/metadata/hub/alice":  profileWire,
			"docker/auth/metadata/hub/broken": `not json`,
		})
		profiles, err := hub(t, engine).ListProfiles(t.Context())
		require.NoError(t, err)
		require.Len(t, profiles, 1)
		assert.Equal(t, "alice", profiles[0].Username)
	})
	t.Run("all entries undecodable", func(t *testing.T) {
		engine := serving(map[string]string{
			"docker/auth/metadata/hub/broken": `not json`,
		})
		_, err := hub(t, engine).ListProfiles(t.Context())
		require.ErrorContains(t, err, "decode profile metadata")
	})
	t.Run("engine unavailable", func(t *testing.T) {
		_, err := hub(t, fakeEngine{err: client.ErrSecretsEngineNotAvailable}).ListProfiles(t.Context())
		require.ErrorIs(t, err, client.ErrSecretsEngineNotAvailable)
	})
}

func TestStaging(t *testing.T) {
	t.Parallel()
	engine := serving(map[string]string{
		"docker/auth/metadata/hub-staging/default": `{"user_id":"docker/auth/hub-staging/alice"}`,
		"docker/auth/hub-staging/alice":            sessionWire,
	})

	session, err := hub(t, engine, dockerhub.Staging()).GetDefaultSession(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "token-alice", session.AccessToken)

	session, err = hub(t, engine, dockerhub.Staging()).GetSession(t.Context(), "alice")
	require.NoError(t, err)
	assert.Equal(t, "token-alice", session.AccessToken)
}

func TestClaimsRoundTrip(t *testing.T) {
	t.Parallel()
	var session dockerhub.UserSession
	require.NoError(t, json.Unmarshal([]byte(sessionWire), &session))

	data, err := json.Marshal(session.Claims)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"exp":1755500000`)
	assert.Contains(t, string(data), `"aud":["audience.docker.io"]`)

	var claims dockerhub.Claims
	require.NoError(t, json.Unmarshal(data, &claims))
	assert.Equal(t, session.Claims.ExpiresAt.Unix(), claims.ExpiresAt.Unix())
	assert.Equal(t, session.Claims.Audience, claims.Audience)
	assert.Equal(t, session.Claims.Username, claims.Username)
}

func TestNumericDate(t *testing.T) {
	t.Parallel()
	t.Run("rejects out of range epochs", func(t *testing.T) {
		var date dockerhub.NumericDate
		for _, wire := range []string{`1e19`, `-1e19`, `10000000000000000000`, `9223372036854775807`} {
			require.ErrorContains(t, json.Unmarshal([]byte(wire), &date), "out of range", wire)
		}
	})
	t.Run("parses fractional seconds", func(t *testing.T) {
		var date dockerhub.NumericDate
		require.NoError(t, json.Unmarshal([]byte(`1755500000.1`), &date))
		assert.InDelta(t, 100000000, date.Nanosecond(), 200)
		assert.Equal(t, int64(1755500000), date.Unix())
	})
	t.Run("exponent form", func(t *testing.T) {
		var date dockerhub.NumericDate
		require.NoError(t, json.Unmarshal([]byte(`1.7555e9`), &date))
		assert.Equal(t, int64(1755500000), date.Unix())
	})
	t.Run("null is a no-op", func(t *testing.T) {
		date := dockerhub.NumericDate{Time: time.Unix(5, 0)}
		require.NoError(t, json.Unmarshal([]byte(`null`), &date))
		assert.Equal(t, int64(5), date.Unix())
	})
	t.Run("marshal truncates to whole seconds", func(t *testing.T) {
		date := dockerhub.NumericDate{Time: time.Unix(1755500000, 500000000)}
		data, err := json.Marshal(date)
		require.NoError(t, err)
		assert.Equal(t, `1755500000`, string(data))
	})
}

func TestAudienceDecoding(t *testing.T) {
	t.Parallel()
	var audience dockerhub.Audience
	require.NoError(t, json.Unmarshal([]byte(`null`), &audience))
	assert.Nil(t, audience)
	require.Error(t, json.Unmarshal([]byte(`{"not":"audience"}`), &audience))
	require.Error(t, json.Unmarshal([]byte(`[1]`), &audience))
}
