package ipc

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/docker/secrets-engine/internal/api"
)

type PluginConfigFromEngine struct {
	Name                string        `json:"name"`
	RegistrationTimeout time.Duration `json:"timeout"`
	Custom
}

func (c *PluginConfigFromEngine) ToString() (string, error) {
	result, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return string(result), nil
}

func NewPluginConfigFromEngineEnv(in string) (*PluginConfigFromEngine, error) {
	var result PluginConfigFromEngine
	if err := json.Unmarshal([]byte(in), &result); err != nil {
		return nil, fmt.Errorf("failed to decode plugin config from engine %q: %w", api.PluginLaunchedByEngineVar, err)
	}
	if result.Name == "" {
		return nil, errors.New("plugin name is required")
	}
	if result.RegistrationTimeout == 0 {
		return nil, errors.New("plugin registration timeout is required")
	}
	if err := result.isValid(); err != nil {
		return nil, err
	}
	return &result, nil
}

type PipeConn struct {
	R *os.File
	W *os.File
}

func (p *PipeConn) Read(b []byte) (int, error)  { return p.R.Read(b) }
func (p *PipeConn) Write(b []byte) (int, error) { return p.W.Write(b) }
func (p *PipeConn) Close() error {
	return errors.Join(p.R.Close(), p.W.Close())
}
