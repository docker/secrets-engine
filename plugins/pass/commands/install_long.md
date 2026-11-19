Builds a secrets engine plugin from Go source with `go install` and copies the
binary into the engine's plugin directory.

PACKAGE is a Go package path, optionally with a version
(`github.com/docker/secrets-engine/plugins/stdinreader@v0.1.0`; the default is
`@latest`). A PACKAGE that starts with `.` or `/` is a local directory that
holds a main package.

The build runs in a temporary directory. The binary is installed only if it is
a Go program that uses the plugin SDK
(`github.com/docker/secrets-engine/plugin`). The file name becomes the plugin
name; set it with `--name`.

Requires the Go toolchain. If the plugin directory is not writable, the final
copy runs through `sudo`.

The engine loads plugins at startup, so restart it afterwards.
