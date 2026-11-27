# stdinreader

The stdinreader plugin serves secrets that it reads from standard input. It
suits CI: a job pipes its secrets in once, and later steps reference them as
`se://NAME`.

At startup it reads the secrets, connects to the standalone Secrets Engine at
[`config.StandaloneSocketPath`](../../client/config), and registers as
`stdinreader`. It keeps the secrets in memory and serves all of them until it
receives SIGINT or SIGTERM. It does not reach Docker Desktop's engine, which
listens on another socket.

## Usage

With the engine running, from a checkout of this repository:

```console
$ printf 'DB_TOKEN=hunter2\n' | go run ./plugins/stdinreader
```

While the plugin runs, the engine resolves `se://DB_TOKEN` to `hunter2`.

Start the plugin yourself. A copy that the engine launches from its plugin
directory gets an empty stdin and exits.

## Input

Stdin holds one `KEY=VALUE` pair per line. Each key must be a valid secret ID.

- Blank lines and lines that start with `#` are skipped.
- A leading `export ` is dropped.
- Matching single or double quotes around a value are removed.
- Values are taken literally: the plugin expands no variables and interprets
  no escape sequences.
