package secretservice

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUnixSocketPath covers parsing of a single DBUS_SESSION_BUS_ADDRESS entry:
// it must extract the filesystem path of a "unix:path=" endpoint (unescaping %XX
// values) and report ok=false for abstract sockets, tcp endpoints, and entries
// with no path key.
func TestUnixSocketPath(t *testing.T) {
	tests := []struct {
		name     string
		entry    string
		wantPath string
		wantOK   bool
	}{
		{name: "plain unix path", entry: "unix:path=/run/user/1000/bus", wantPath: "/run/user/1000/bus", wantOK: true},
		{name: "path with extra keys", entry: "unix:path=/run/user/1000/bus,guid=deadbeef", wantPath: "/run/user/1000/bus", wantOK: true},
		{name: "escaped path", entry: "unix:path=/tmp/dbus%2dtest", wantPath: "/tmp/dbus-test", wantOK: true},
		{name: "abstract socket has no fs path", entry: "unix:abstract=/tmp/dbus-Ab12Cd", wantOK: false},
		{name: "tcp endpoint", entry: "tcp:host=localhost,port=12345", wantOK: false},
		{name: "empty entry", entry: "", wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, ok := unixSocketPath(tt.entry)
			assert.Equal(t, tt.wantOK, ok)
			if tt.wantOK {
				assert.Equal(t, tt.wantPath, path)
			}
		})
	}
}

// TestSessionBusMissingSocket covers the pre-dial fast-fail decision that backs
// NewService. It must report "missing" ONLY when every endpoint is a unix socket
// path that does not exist (dialing is guaranteed to fail); it must fall through
// to a normal dial (ok=false) for an unset/autolaunch address, an endpoint it
// cannot stat (abstract, tcp), or any endpoint whose socket exists — even when a
// sibling endpoint's socket is missing. That last case is the regression this
// test guards: godbus dials the first *connectable* endpoint, so a live abstract
// socket beside a stale unix:path must NOT be reported unavailable.
func TestSessionBusMissingSocket(t *testing.T) {
	// A path that exists (a regular file suffices; the check only stats it).
	live := filepath.Join(t.TempDir(), "bus")
	require.NoError(t, os.WriteFile(live, nil, 0o600))
	const gone = "/nonexistent/dbus/socket-abc123"
	const gone2 = "/nonexistent/dbus/socket-def456"

	tests := []struct {
		name        string
		addr        string
		wantMissing bool
	}{
		{name: "unset", addr: "", wantMissing: false},
		{name: "autolaunch", addr: "autolaunch:", wantMissing: false},
		{name: "single missing path", addr: "unix:path=" + gone, wantMissing: true},
		{name: "single existing path", addr: "unix:path=" + live, wantMissing: false},
		{name: "all missing paths", addr: "unix:path=" + gone + ";unix:path=" + gone2, wantMissing: true},
		{name: "abstract alongside missing path is not conclusive", addr: "unix:abstract=/tmp/dbus-live;unix:path=" + gone, wantMissing: false},
		{name: "existing path alongside missing path is not conclusive", addr: "unix:path=" + live + ";unix:path=" + gone, wantMissing: false},
		{name: "tcp endpoint is not conclusive", addr: "tcp:host=localhost,port=1", wantMissing: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("DBUS_SESSION_BUS_ADDRESS", tt.addr)
			_, missing := sessionBusMissingSocket()
			assert.Equal(t, tt.wantMissing, missing)
		})
	}
}
