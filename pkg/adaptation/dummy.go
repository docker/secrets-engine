package adaptation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/docker/secrets-engine/pkg/secrets"
	"github.com/docker/secrets-engine/plugin"
)

const (
	dummyPluginCfgEnv = "DUMMY_PLUGIN_CFG"
)

func DummyPluginCommand(t *testing.T, cfg dummyPluginCfg) (*exec.Cmd, func() (*dummyPluginResult, error)) {
	t.Helper()
	cfgStr, err := cfg.toString()
	assert.NoError(t, err)
	cmd := exec.Command(os.Args[0]) // run the test binary again
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	cmd.Env = append(os.Environ(),
		"RUN_AS_DUMMY_PLUGIN=1",
		dummyPluginCfgEnv+"="+cfgStr,
	)
	return cmd, func() (*dummyPluginResult, error) {
		if stdErr := stderrBuf.String(); stdErr != "" {
			return nil, errors.New(stdErr)
		}
		var result dummyPluginResult
		stdOut := stdoutBuf.String()
		if err := json.Unmarshal([]byte(stdOut), &result); err != nil {
			return nil, fmt.Errorf("failed to unmarshal '%s': %w", stdOut, err)
		}
		return &result, nil
	}
}

var _ plugin.Plugin = &dummyPlugin{}

type dummyPlugin struct {
	m      sync.Mutex
	cfg    dummyPluginCfg
	result dummyPluginResult
}

type dummyPluginResult struct {
	GetSecret        []secrets.Request
	ConfigRequests   int
	Configure        []plugin.RuntimeConfig
	ShutdownRequests int
	Log              string
}

func (r *dummyPluginResult) prettyPrintLogs() {
	fmt.Println("--- dummy plugin logs ---")
	fmt.Println(r.Log)
}

func (d *dummyPlugin) GetSecret(_ context.Context, request secrets.Request) (secrets.Envelope, error) {
	d.m.Lock()
	defer d.m.Unlock()
	d.result.GetSecret = append(d.result.GetSecret, request)
	if d.cfg.ErrGetSecret != "" {
		return secrets.Envelope{}, errors.New(d.cfg.ErrGetSecret)
	}
	return *d.cfg.E, nil
}

func (d *dummyPlugin) Config() plugin.Config {
	d.m.Lock()
	defer d.m.Unlock()
	d.result.ConfigRequests++
	return d.cfg.Config
}

func (d *dummyPlugin) Configure(_ context.Context, config plugin.RuntimeConfig) error {
	d.m.Lock()
	defer d.m.Unlock()
	d.result.Configure = append(d.result.Configure, config)
	if d.cfg.ErrConfigure != "" {
		return errors.New(d.cfg.ErrConfigure)
	}
	return nil
}

func (d *dummyPlugin) Shutdown(context.Context) {
	d.m.Lock()
	defer d.m.Unlock()
	d.result.ShutdownRequests++
}

type dummyPluginCfg struct {
	plugin.Config `json:",inline"`
	E             *secrets.Envelope `json:"envelope,omitempty"`
	ErrGetSecret  string            `json:"errGetSecret,omitempty"`
	ErrConfigure  string            `json:"errConfigure,omitempty"`
}

func (c *dummyPluginCfg) toString() (string, error) {
	result, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return string(result), nil
}

func newDummyPluginCfg(in string) (*dummyPluginCfg, error) {
	var result dummyPluginCfg
	if err := json.Unmarshal([]byte(in), &result); err != nil {
		return nil, fmt.Errorf("failed to decode dummy plugin cfg: %w", err)
	}
	return &result, nil
}

func DummyPluginProcess() {
	var logBuf bytes.Buffer
	logrus.SetOutput(&logBuf)
	cfgStr := os.Getenv(dummyPluginCfgEnv)
	cfg, err := newDummyPluginCfg(cfgStr)
	if err != nil {
		panic(err)
	}
	d := &dummyPlugin{cfg: *cfg}
	p, err := plugin.New(d)
	if err != nil {
		panic(err)
	}
	if err := p.Run(context.Background()); err != nil {
		panic(err)
	}
	result := d.result
	result.Log = logBuf.String()
	resultStr, err := json.Marshal(result)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(resultStr))
}
