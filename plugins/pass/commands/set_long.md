Stores a secret in the local OS keychain. Three ways to pass the value:
  - `docker pass set NAME` prompts for it when standard input is a terminal.
    Typed or pasted input is masked.
  - `... | docker pass set NAME` or `docker pass set NAME < file` reads it
    from standard input. Use this for scripts and for multi-line or binary
    values.
  - `docker pass set NAME=VALUE` sets it inline. Avoid this in an interactive
    shell as the value ends up in your shell history.

Pass `--force` to overwrite an existing secret. Without it, macOS (Keychain)
refuses with a duplicate-item error, while Linux (Secret Service) and Windows
(Credential Manager) overwrite silently. The replacement is atomic except on
macOS, where the Keychain API deletes the old item before adding the new one.
