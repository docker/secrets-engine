package adaptation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/pkg/api"
	"github.com/docker/secrets-engine/pkg/secrets"
	"github.com/docker/secrets-engine/plugin"
)

const (
	dummyPluginCfgEnv = "DUMMY_PLUGIN_CFG"
	dummyPluginFail   = "plugin-fail"
	mockVersion       = "mockVersion"
	mockSecretValue   = "mockSecretValue"
	mockSecretID      = secrets.ID("mockSecretID")
	mockPattern       = "mockPattern"
)

// Configures and runs a dummy plugin process.
// To be used from TestMain.
func dummyPluginProcessFromBinaryName(name string) {
	if strings.HasPrefix(name, "plugin-") && name != dummyPluginFail {
		val := strings.TrimPrefix(name, "plugin-")
		dummyPluginProcess(&dummyPluginCfg{
			Config: plugin.Config{
				Version: mockVersion,
				Pattern: "*",
			},
			E: []secrets.Envelope{
				{ID: secrets.ID(val), Value: []byte(val + "-value")},
				{ID: mockSecretID, Value: []byte(mockSecretValue)},
			},
		})
	} else {
		dummyPluginProcess(&dummyPluginCfg{ErrConfigPanic: "fake crash"})
	}
}

type dummyPlugins struct {
	failPlugin bool
	okPlugins  []string
}

// Use it in a test to create a set of dummy plugins that behave like normal plugins
// but under the hood re-use the test binary.
// This is the counterpart to dummyPluginProcessFromBinaryName().
func createDummyPlugins(t *testing.T, cfg dummyPlugins) string {
	t.Helper()
	exe, err := os.Executable()
	assert.NoError(t, err)
	dir := t.TempDir()
	if cfg.failPlugin {
		assert.NoError(t, os.Symlink(exe, filepath.Join(dir, dummyPluginFail)))
	}
	for _, p := range cfg.okPlugins {
		require.True(t, strings.HasPrefix(p, "plugin-"))
		assert.NoError(t, os.Symlink(exe, filepath.Join(dir, p)))
	}
	return dir
}

// dummyPluginCommand can be called from within tests. The returned *exec.Cmd runs the dummyPluginProcess()
// that implements the plugin.Plugin interface, i.e., we get a normal external plugin binary.
// Under the hood, it re-runs the existing test binary (created by go test) with different parameters.
// The TestMain acts as a switch to then instead running as normal test to run dummyPluginProcess().
func dummyPluginCommand(t *testing.T, cfg dummyPluginCfg) (*exec.Cmd, func() (*dummyPluginResult, error)) {
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
		t.Helper()
		if stdErr := stderrBuf.String(); stdErr != "" {
			return nil, errors.New(stdErr)
		}
		var result dummyPluginResult
		stdOut := stdoutBuf.String()
		if err := json.Unmarshal([]byte(stdOut), &result); err != nil {
			return nil, fmt.Errorf("failed to unmarshal '%s': %w", stdOut, err)
		}
		if result.ErrTestSetup != "" {
			return nil, errors.New(result.ErrTestSetup)
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
	ShutdownRequests int
	Log              string
	ErrTestSetup     string
}

func (d *dummyPlugin) GetSecret(_ context.Context, request secrets.Request) (secrets.Envelope, error) {
	d.m.Lock()
	defer d.m.Unlock()
	d.result.GetSecret = append(d.result.GetSecret, request)
	if d.cfg.ErrGetSecret != "" {
		return secrets.Envelope{}, errors.New(d.cfg.ErrGetSecret)
	}
	for _, s := range d.cfg.E {
		if request.ID == s.ID {
			s.CreatedAt = time.Now().Add(-time.Hour)
			s.ExpiresAt = time.Now().Add(time.Hour)
			return s, nil
		}
	}
	err := errors.New("secret not found")
	return api.EnvelopeErr(request, err), err
}

func (d *dummyPlugin) Config() plugin.Config {
	d.m.Lock()
	defer d.m.Unlock()
	if d.cfg.ErrConfigPanic != "" {
		panic(errors.New(d.cfg.ErrConfigPanic))
	}
	d.result.ConfigRequests++
	return d.cfg.Config
}

func (d *dummyPlugin) Shutdown(context.Context) {
	d.m.Lock()
	defer d.m.Unlock()
	d.result.ShutdownRequests++
}

type dummyPluginCfg struct {
	plugin.Config  `json:",inline"`
	E              []secrets.Envelope `json:"envelope,omitempty"`
	ErrGetSecret   string             `json:"errGetSecret,omitempty"`
	IgnoreSigint   bool               `json:"ignoreSigint,omitempty"`
	ErrConfigPanic string             `json:"errConfigPanic,omitempty"`
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

func getCfgFromEnv() *dummyPluginCfg {
	cfgStr := os.Getenv(dummyPluginCfgEnv)
	cfg, err := newDummyPluginCfg(cfgStr)
	if err != nil {
		tryExitWithTestSetupErr(err)
	}
	return cfg
}

// This is the equivalent of a main when normally implementing a plugin.
// Here, it gets run by TestMain if dummyPluginCommand is used to re-launch the test binary (the binary built by go test).
func dummyPluginProcess(cfg *dummyPluginCfg) {
	var logBuf bytes.Buffer
	logrus.SetOutput(&logBuf)
	if cfg == nil {
		cfg = getCfgFromEnv()
	}

	ctx := context.Background()
	if !cfg.IgnoreSigint {
		ctxWithCancel, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()
		ctx = ctxWithCancel
	}

	d := &dummyPlugin{cfg: *cfg}
	p, err := plugin.New(d)
	if err != nil {
		tryExitWithTestSetupErr(err)
	}
	if err := p.Run(ctx); err != nil {
		tryExitWithTestSetupErr(err)
	}
	result := d.result
	result.Log = logBuf.String()
	resultStr, err := json.Marshal(result)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(resultStr))
}

func tryExitWithTestSetupErr(err error) {
	str, err := json.Marshal(dummyPluginResult{ErrTestSetup: err.Error()})
	if err != nil {
		panic(err)
	}
	fmt.Println(string(str))
	os.Exit(1)
}
