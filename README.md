Docker Secrets Engine
=====================

The _Secrets Engine_ provides an end to end playground to demonstrate and
implement the concept of Docker secrets. Docker secrets have been around since
swarm but haven't been fully integrated into the swarmless ecosystem.

Running the example
-------------------

The best way to get a handle on this is to compile the plugin:

```console
go build ./cmd/docker-secrets/
```

You can move it into the plugin location but its not necessary (and may not
work).

To start, create a few secrets in your keychain:

```console
echo asdf | ./docker-secrets set foo/bar -
echo asdf | ./docker-secrets set foo/baz -
```

There might be a bug with the keychain where you have to enter your password a
few times but follow through on it and hit always allow if it gets annoying. We
likely need to investigate a bug in the keychain package, as this is a problem
with the cred helper stack, as well.

Now, we can access the secrets from a container:

```console
❯ ./docker-secrets run --secret foo/bar --secret-env FOO_BAR=foo/bar debian
2025/05/12 19:27:33 INFO running docker command cmd="/usr/local/bin/docker run -it --rm -v /var/folders/ll/dx4rytps31j5ns9pdbtn9g1h0000gp/T/docker-secrets-1703750799/api.sock:/run/secrets.sock -v /var/folders/ll/dx4rytps31j5ns9pdbtn9g1h0000gp/T/docker-secrets-1703750799/secrets:/run/secrets --env SECRETS_SOCK=/run/secrets.sock --env FOO_BAR=asdf\n debian"
root@c1d2b75b4bb3:/# env
HOSTNAME=c1d2b75b4bb3
FOO_BAR=asdf

PWD=/
HOME=/root
TERM=xterm
SHLVL=1
SECRETS_SOCK=/run/secrets.sock
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
_=/usr/bin/env
root@c1d2b75b4bb3:/# ls /run/secrets
foo
root@c1d2b75b4bb3:/# cat /run/secrets/foo/bar
asdf
```

In the above example, we can see both the file-based secret, which is the
default and the explicit env secret. Selecting these secrets also makes them
available via the API but only for the secrets we selected:

```console
root@c1d2b75b4bb3:/# apt update -q && apt install -y -q curl jq
...
root@c1d2b75b4bb3:/# curl --unix-socket $SECRETS_SOCK http://localhost/secrets/resolve?id=foo/bar
{"Secrets":[{"ID":"foo/bar","Value":"YXNkZgo=","Provider":"local","CreatedAt":"2025-05-05T17:55:36-07:00","ResolvedAt":"2025-05-13T02:29:43.221382Z"}]}
```

If you decode `YXNkZgo=`, you'll find the correct secret value:

```console
root@867d06fbeaaa:/# curl -s --unix-socket $SECRETS_SOCK http://localhost/secrets/resolve?id=foo/bar | jq -r 'map(.[].Value | @base64d)[]'
asdf
```

Remember when we created the `foo/baz` secret? That is inaccesible, since we
did not allow it:

```console
root@c1d2b75b4bb3:/# curl --unix-socket $SECRETS_SOCK http://localhost/secrets/resolve?id=foo/baz
{"Secrets":[{"ID":"foo/baz","Error":"secret foo/baz not available: access denied"}]}
```

To allow secrets but not map them to files or env vars, you can use `--secret-allow <id>`:

```console
❯ ./docker-secrets run --secret foo/bar --secret-env FOO_BAR=foo/bar --secret-allow foo/baz debian
root@2613fb31f0b3:/# curl -sL  --unix-socket $SECRETS_SOCK 'http://localhost/secrets/resolve?id=foo/bar&id=foo/baz' | jq .
{
  "Secrets": [
    {
      "ID": "foo/bar",
      "Value": "YXNkZgo=",
      "Provider": "local",
      "CreatedAt": "2025-05-05T17:55:36-07:00",
      "ResolvedAt": "2025-05-13T02:41:17.081527Z"
    },
    {
      "ID": "foo/baz",
      "Value": "YXNkZgo=",
      "Provider": "local",
      "CreatedAt": "2025-05-05T17:55:39-07:00",
      "ResolvedAt": "2025-05-13T02:41:17.084498Z"
    }
  ]
}
```
