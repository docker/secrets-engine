### Using keychain secrets in containers

Create a secret:

```console
$ docker pass set GH_TOKEN=123456789
```

Create a secret from STDIN:

```console
echo "my_val" | docker pass set GH_TOKEN
```

Run a container that uses the secret:

```console
$ docker run -e GH_TOKEN= -dt --name demo busybox
```

Inspect the secret from inside the container:

```console
$ docker exec demo sh -c 'echo $GH_TOKEN'
123456789
```

Explicitly assign a secret to a different environment variable:

```console
$ docker run -e GITHUB_TOKEN=se://GH_TOKEN -dt --name demo busybox
```

### Using keychain secrets in Compose

Store the secrets:

```console
$ docker pass set myapp/anthropic/api-key=sk-ant-...
$ docker pass set myapp/postgres/password=s3cr3t
```

```yaml
services:
  api:
    image: service1
    environment:
      - ANTHROPIC_API_KEY=se://myapp/anthropic/api-key
      - POSTGRES_PASSWORD=se://myapp/postgres/password

  worker:
    image: service2
    command: worker
    environment:
      - ANTHROPIC_API_KEY=se://myapp/anthropic/api-key

  db:
    image: postgres:17
    environment:
      - POSTGRES_PASSWORD=se://myapp/postgres/password
```
