### Show a secret with its value masked:

```console
$ docker pass get POSTGRES_PASSWORD
```

### Show the secret value in plaintext:

```console
$ docker pass get --reveal POSTGRES_PASSWORD
```
