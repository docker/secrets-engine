### Run a command with one secret in its environment:

```console
$ docker pass run -e GH_TOKEN=se://gh-token -- gh repo list
```

### Pass several secrets to a shell script, which reads them like any other variable:

```console
$ docker pass run -e DB_PASSWORD=se://myapp/password -e API_KEY=se://myapp/api-key -- ./deploy.sh
```

### Resolve references from a dotenv file:

```console
$ docker pass run --env-file .env -- ./deploy.sh
```

### Inline shell (single quotes leave `$DB_PASSWORD` for the child shell to expand):

```console
$ docker pass run -e DB_PASSWORD=se://myapp/password -- sh -c 'pg_dump "postgres://app:$DB_PASSWORD@db/app" > backup.sql'
```

### Wildcard pattern (the first matching secret is used):

```console
$ docker pass run -e DB_PASSWORD=se://*/password -- ./deploy.sh
```

### References already in the calling environment are resolved too:

```console
$ GH_TOKEN=se://gh-token docker pass run -- gh repo list
```

### Combine sources (`--env` overrides `--env-file`; later files override earlier ones; all override the process environment):

```console
$ docker pass run --env-file .env --env-file .env.local -e DB_PASSWORD=se://myapp/postgres/password -- ./deploy.sh
```
