Scans the current environment (plus any `--env-file` inputs) for variables
whose value is exactly `se://<ID|pattern>` and resolves each reference before
launching the child process. The child inherits stdin, stdout, and stderr.

By default, references are resolved through the secrets-engine daemon (Docker
Desktop must be running). Pass `--os-keychain` to resolve directly from the
local OS keychain instead, with no daemon required.

If any reference cannot be resolved, the command fails before the child is
started and exits non-zero.
