### Install the latest version of the stdinreader plugin:

```console
$ docker pass install github.com/docker/secrets-engine/plugins/stdinreader
```

### Install a specific version:

```console
$ docker pass install github.com/docker/secrets-engine/plugins/stdinreader@v0.1.0
```

### Build and install it from a checkout of docker/secrets-engine:

```console
$ docker pass install ./plugins/stdinreader
```

### Install it under a different plugin name:

```console
$ docker pass install --name stdin ./plugins/stdinreader
```
