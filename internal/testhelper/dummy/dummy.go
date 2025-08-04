package dummy

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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/secrets-engine/internal/api"
	"github.com/docker/secrets-engine/internal/logging"
	"github.com/docker/secrets-engine/internal/secrets"
	"github.com/docker/secrets-engine/plugin"
)

const (
	dummyPluginCfgEnv = "DUMMY_PLUGIN_CFG"
	dummyPluginFail   = "plugin-fail"

	MockSecretValue = "MockSecretValue"
	MockSecretID    = secrets.ID("MockSecretID")
)

// PluginProcessFromBinaryName configures and runs a dummy plugin process.
// To be used from TestMain.
func PluginProcessFromBinaryName(name string) {
	name = strings.TrimSuffix(name, suffix)
	if strings.HasPrefix(name, "plugin-") && name != dummyPluginFail {
		val := strings.TrimPrefix(name, "plugin-")
		behaviour, err := ParsePluginBehaviour(val)
		if err != nil {
			panic(err)
		}
		PluginProcess(&PluginCfg{
			Version: "1",
			Pattern: "*",
			Secrets: map[string]string{
				behaviour.Value:      behaviour.Value + "-value",
				string(MockSecretID): MockSecretValue,
			},
			CrashBehaviour: behaviour.CrashBehaviour,
		})
	} else {
		PluginProcess(&PluginCfg{ErrConfigPanic: "fake crash"})
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

var _ plugin.Plugin = &dummyPlugin{}

type dummyPlugin struct {
	m      sync.Mutex
	cfg    PluginCfg
	result PluginResult
}

type PluginResult struct {
	GetSecret    []string
	Log          string
	ErrTestSetup string
}

func (d *dummyPlugin) GetSecret(_ context.Context, request secrets.Request) (secrets.Envelope, error) {
	d.m.Lock()
	defer d.m.Unlock()
	if d.cfg.CrashBehaviour != nil && len(d.result.GetSecret)+1 >= d.cfg.OnNthSecretRequest {
		os.Exit(d.cfg.ExitCode)
	}
	d.result.GetSecret = append(d.result.GetSecret, request.ID.String())
	if d.cfg.ErrGetSecret != "" {
		return secrets.Envelope{}, errors.New(d.cfg.ErrGetSecret)
	}
	if v, ok := d.cfg.Secrets[string(request.ID)]; ok {
		return secrets.Envelope{
			ID:        request.ID,
			Value:     []byte(v),
			CreatedAt: time.Now().Add(-time.Hour),
			ExpiresAt: time.Now().Add(-time.Hour),
		}, nil
	}
	err := errors.New("secret not found")
	return secrets.EnvelopeErr(request, err), err
}

type PluginCfg struct {
	Version        string            `json:"version"`
	Pattern        string            `json:"pattern"`
	Secrets        map[string]string `json:"secrets"`
	ErrGetSecret   string            `json:"errGetSecret,omitempty"`
	IgnoreSigint   bool              `json:"ignoreSigint,omitempty"`
	ErrConfigPanic string            `json:"errConfigPanic,omitempty"`
	*CrashBehaviour
}

func (c *PluginCfg) toString() (string, error) {
	result, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return string(result), nil
}

func newDummyPluginCfg(in string) (*PluginCfg, error) {
	var result PluginCfg
	if err := json.Unmarshal([]byte(in), &result); err != nil {
		return nil, fmt.Errorf("failed to decode dummy plugin cfg: %w", err)
	}
	return &result, nil
}

func getCfgFromEnv() *PluginCfg {
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

// PluginProcess is the equivalent of a main when normally implementing a plugin.
// Here, it gets run by TestMain if PluginCommand is used to re-launch the test binary (the binary built by go test).
func PluginProcess(cfg *PluginCfg) {
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
	version, err := api.NewVersion(cfg.Version)
	if err != nil {
		panic(err)
	}
	pattern, err := secrets.ParsePattern(cfg.Pattern)
	if err != nil {
		panic(err)
	}
	p, err := plugin.New(d, plugin.Config{Version: version, Pattern: pattern, Logger: logger})
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
	*CrashBehaviour
}

type CrashBehaviour struct {
	OnNthSecretRequest int `json:"on_nth_secret_request"`
	ExitCode           int `json:"exit_code"`
}

func (p PluginBehaviour) ToString() (string, error) {
	if strings.Contains(p.Value, "-") {
		return "", errors.New("no '-' in plugin value allowed")
	}
	if p.CrashBehaviour == nil {
		return p.Value, nil
	}
	return fmt.Sprintf("%s-%d-%d", p.Value, p.OnNthSecretRequest, p.ExitCode), nil
}

func ParsePluginBehaviour(s string) (PluginBehaviour, error) {
	parts := strings.Split(s, "-")
	if len(parts) == 1 {
		return PluginBehaviour{Value: s}, nil
	}
	if len(parts) != 3 {
		return PluginBehaviour{}, fmt.Errorf("invalid format: expected 3 parts, got %d", len(parts))
	}

	exitN, err := strconv.Atoi(parts[1])
	if err != nil {
		return PluginBehaviour{}, fmt.Errorf("invalid exit count %q: %w", parts[1], err)
	}

	exitCode, err := strconv.Atoi(parts[2])
	if err != nil {
		return PluginBehaviour{}, fmt.Errorf("invalid exit code %q: %w", parts[2], err)
	}

	return PluginBehaviour{
		parts[0],
		&CrashBehaviour{OnNthSecretRequest: exitN, ExitCode: exitCode},
	}, nil
}
