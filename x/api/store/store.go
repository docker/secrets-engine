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

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/docker/secrets-engine/x/secrets"
)

var _ secrets.Writer = &storeClient{}

type storeClient struct {
	httpClient *http.Client
}

// NewStoreClient returns a [secrets.Writer] that POSTs to the engine's
// /internal/secrets endpoint using the provided HTTP client.
//
// The HTTP client must be configured with a unix-socket dial function pointing
// at the engine socket (see the client package).
func NewStoreClient(httpClient *http.Client) secrets.Writer {
	return &storeClient{httpClient: httpClient}
}

type storeRequest struct {
	ID       string            `json:"id"`
	Value    string            `json:"value"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

func (c *storeClient) SaveSecret(ctx context.Context, id secrets.ID, value []byte, metadata map[string]string, overwrite bool) error {
	body, err := json.Marshal(storeRequest{
		ID:       id.String(),
		Value:    string(value),
		Metadata: metadata,
	})
	if err != nil {
		return fmt.Errorf("marshaling store request: %w", err)
	}

	endpoint := "http://unix/internal/secrets"
	if overwrite {
		endpoint += "?overwrite=true"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building store request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusCreated {
		return nil
	}

	var errResp struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&errResp)

	switch resp.StatusCode {
	case http.StatusConflict:
		return fmt.Errorf("%w: %s", secrets.ErrAlreadyExists, errResp.Error)
	case http.StatusBadRequest:
		return fmt.Errorf("invalid request: %s", errResp.Error)
	default:
		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, errResp.Error)
	}
}
