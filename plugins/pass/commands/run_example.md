### Run a command with one secret in its environment:

```console
$ SE_TOKEN=se://gh-token docker pass run -- gh repo list
```

### Multiple references:

```console
$ DB_PASSWORD=se://myapp/postgres/password API_KEY=se://myapp/anthropic/api-key docker pass run -- ./my-binary
```

### Resolve references from a dotenv file:

```console
$ docker pass run --env-file .env -- ./my-binary
```

### Multiple files (later overrides earlier; files override the process environment):

```console
$ docker pass run --env-file .env --env-file .env.local -- ./my-binary
```
