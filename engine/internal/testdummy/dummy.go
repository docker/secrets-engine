package testdummy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/plugin"
	"github.com/docker/secrets-engine/x/api"
	"github.com/docker/secrets-engine/x/logging"
	"github.com/docker/secrets-engine/x/secrets"
)

const (
	dummyPluginCfgEnv = "DUMMY_PLUGIN_CFG"
	dummyPluginFail   = "plugin-fail"

	MockSecretValue = "MockSecretValue"
)

var (
	MockSecretID      = secrets.MustParseID("MockSecretID")
	MockSecretPattern = secrets.MustParsePattern("MockSecretID")
)

// pluginProcessFromBinaryName configures and runs a dummy plugin process.
func pluginProcessFromBinaryName(name string) {
	name = strings.TrimSuffix(name, suffix)
	if strings.HasPrefix(name, "plugin-") && name != dummyPluginFail {
		val := strings.TrimPrefix(name, "plugin-")
		behaviour, err := ParsePluginBehaviour(val)
		if err != nil {
			panic(err)
		}
		pluginProcess(&pluginCfgRestored{
			version: api.MustNewVersion("v1"),
			pattern: secrets.MustParsePattern("*"),
			secrets: map[secrets.ID]string{
				secrets.MustParseID(behaviour.Value): behaviour.Value + "-value",
				MockSecretID:                         MockSecretValue,
			},
		})
	} else {
		pluginProcess(&pluginCfgRestored{ErrConfigPanic: "fake crash"})
	}
}

type Plugins struct {
	FailPlugin bool
	Plugins    []PluginBehaviour
}

// CreateDummyPlugins Use it in a test to create a set of dummy plugins that behave like normal plugins
// but under the hood re-use the test binary.
// This is the counterpart to dummyPluginProcessFromBinaryName().
func CreateDummyPlugins(t *testing.T, cfg Plugins) string {
	t.Helper()
	exe, err := os.Executable()
	assert.NoError(t, err)
	dir := t.TempDir()
	if cfg.FailPlugin {
		assert.NoError(t, copyFile(exe, filepath.Join(dir, dummyPluginFail+suffix)))
	}
	for _, p := range cfg.Plugins {
		s, err := p.ToString()
		require.NoError(t, err)
		assert.NoError(t, copyFile(exe, filepath.Join(dir, "plugin-"+s+suffix)))
	}
	return dir
}

func copyFile(src, dst string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return err
	}

	if err := os.WriteFile(dst, data, info.Mode().Perm()); err != nil {
		return err
	}
	return nil
}

// TestMain acts as a dispatcher to run as dummy plugin or normal test.
// Inspired by: https://github.com/golang/go/blob/15d9fe43d648764d41a88c75889c84df5e580930/src/os/exec/exec_test.go#L69-L73
func TestMain(m *testing.M) {
	binaryName := getTestBinaryName()
	if strings.HasPrefix(binaryName, "plugin") {
		// This allows tests to call the test binary as plugin by creating a symlink prefixed with "plugin-" to it.
		// We then based on the suffix in dummyPluginProcessFromBinaryName() set the behavior of the plugin.
		pluginProcessFromBinaryName(binaryName)
	} else if os.Getenv("RUN_AS_DUMMY_PLUGIN") != "" {
		// PluginProcess is the equivalent of a main when normally implementing a plugin.
		// Here, it gets run by TestMain if PluginCommand is used to re-launch the test binary (the binary built by go test).
		pluginProcess(nil)
	} else {
		os.Exit(m.Run())
	}
}

func getTestBinaryName() string {
	if len(os.Args) == 0 {
		return ""
	}
	return filepath.Base(os.Args[0])
}

// PluginCommand can be called from within tests. The returned *exec.Cmd runs the PluginProcess()
// that implements the plugin.Plugin interface, i.e., we get a normal external plugin binary.
// Under the hood, it re-runs the existing test binary (created by go test) with different parameters.
// The TestMain acts as a switch to then instead running as normal test to run PluginProcess().
func PluginCommand(t *testing.T, cfg PluginCfg) (*exec.Cmd, func() (*PluginResult, error)) {
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
	return cmd, func() (*PluginResult, error) {
		t.Helper()
		require.NotNil(t, cmd.ProcessState)
		if stdErr := stderrBuf.String(); stdErr != "" {
			return nil, errors.New(stdErr)
		}
		var result PluginResult
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

var _ plugin.ExternalPlugin = &dummyPlugin{}

type dummyPlugin struct {
	m      sync.Mutex
	cfg    pluginCfgRestored
	result PluginResult
}

type PluginResult struct {
	GetSecret    []string
	Log          string
	ErrTestSetup string
}

func (d *dummyPlugin) GetSecrets(_ context.Context, pattern secrets.Pattern) ([]secrets.Envelope, error) {
	d.m.Lock()
	defer d.m.Unlock()
	d.result.GetSecret = append(d.result.GetSecret, pattern.String())
	if d.cfg.errGetSecret != nil {
		return nil, d.cfg.errGetSecret
	}
	var envelopes []secrets.Envelope
	for id, value := range d.cfg.secrets {
		if pattern.Match(id) {
			envelopes = append(envelopes, secrets.Envelope{
				ID:        id,
				Value:     []byte(value),
				CreatedAt: time.Now().Add(-time.Hour),
				ExpiresAt: time.Now().Add(-time.Hour),
			})
		}
	}
	if len(envelopes) == 0 {
		return nil, secrets.ErrNotFound
	}
	return envelopes, nil
}

type PluginCfg struct {
	Version        string            `json:"version"`
	Pattern        string            `json:"pattern"`
	Secrets        map[string]string `json:"secrets"`
	ErrGetSecret   string            `json:"errGetSecret,omitempty"`
	IgnoreSigint   bool              `json:"ignoreSigint,omitempty"`
	ErrConfigPanic string            `json:"errConfigPanic,omitempty"`
}

type pluginCfgRestored struct {
	version        api.Version
	pattern        secrets.Pattern
	secrets        map[secrets.ID]string
	errGetSecret   error
	IgnoreSigint   bool
	ErrConfigPanic string
}

func (c *PluginCfg) toString() (string, error) {
	result, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return string(result), nil
}

func newDummyPluginCfg(in string) (*pluginCfgRestored, error) {
	var cfg PluginCfg
	if err := json.Unmarshal([]byte(in), &cfg); err != nil {
		return nil, fmt.Errorf("failed to decode dummy plugin cfg: %w", err)
	}
	store := map[secrets.ID]string{}
	for idString, secret := range cfg.Secrets {
		id, err := secrets.ParseID(idString)
		if err != nil {
			return nil, err
		}
		store[id] = secret
	}
	version, err := api.NewVersion(cfg.Version)
	if err != nil {
		return nil, err
	}
	pattern, err := secrets.ParsePattern(cfg.Pattern)
	if err != nil {
		return nil, err
	}
	var errGetSecret error
	if cfg.ErrGetSecret != "" {
		errGetSecret = errors.New(cfg.ErrGetSecret)
	}
	return &pluginCfgRestored{
		version:        version,
		pattern:        pattern,
		secrets:        store,
		errGetSecret:   errGetSecret,
		IgnoreSigint:   cfg.IgnoreSigint,
		ErrConfigPanic: cfg.ErrConfigPanic,
	}, nil
}

func getCfgFromEnv() *pluginCfgRestored {
	cfgStr := os.Getenv(dummyPluginCfgEnv)
	cfg, err := newDummyPluginCfg(cfgStr)
	if err != nil {
		tryExitWithTestSetupErr(err)
	}
	return cfg
}

type bufferLogger struct {
	buf *bytes.Buffer
}

func (b *bufferLogger) Printf(format string, v ...interface{}) {
	_, _ = fmt.Fprintf(b.buf, format, v...)
}

func (b *bufferLogger) Warnf(format string, v ...interface{}) {
	b.buf.WriteString("[WARN] " + fmt.Sprintf(format, v...))
}

func (b *bufferLogger) Errorf(format string, v ...interface{}) {
	b.buf.WriteString("[ERR] " + fmt.Sprintf(format, v...))
}

var _ logging.Logger = &bufferLogger{}

func pluginProcess(cfg *pluginCfgRestored) {
	var logBuf bytes.Buffer
	logger := &bufferLogger{&logBuf}
	if cfg == nil {
		cfg = getCfgFromEnv()
	}

	ctx := context.Background()
	if !cfg.IgnoreSigint {
		ctxWithCancel, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		ctx = ctxWithCancel
	}

	d := &dummyPlugin{cfg: *cfg}
	p, err := plugin.New(d, plugin.Config{Version: cfg.version, Pattern: cfg.pattern, Logger: logger})
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
	str, err := json.Marshal(PluginResult{ErrTestSetup: err.Error()})
	if err != nil {
		panic(err)
	}
	fmt.Println(string(str))
	os.Exit(1)
}

type PluginBehaviour struct {
	Value string `json:"value"`
}

func (p PluginBehaviour) ToString() (string, error) {
	if strings.Contains(p.Value, "-") {
		return "", errors.New("no '-' in plugin value allowed")
	}
	return p.Value, nil
}

func ParsePluginBehaviour(s string) (PluginBehaviour, error) {
	parts := strings.Split(s, "-")
	if len(parts) == 1 {
		return PluginBehaviour{Value: s}, nil
	}
	if len(parts) != 3 {
		return PluginBehaviour{}, fmt.Errorf("invalid format: expected 3 parts, got %d", len(parts))
	}

	return PluginBehaviour{parts[0]}, nil
}
