### Set a secret:

```console
$ docker pass set POSTGRES_PASSWORD=my-secret-password
```

### Or pass the secret via STDIN:

```console
$ echo my-secret-password > pwd.txt
$ cat pwd.txt | docker pass set POSTGRES_PASSWORD
```

### Set a secret with metadata:

```console
$ docker pass set POSTGRES_PASSWORD=my-secret-password --metadata owner=alice --metadata expiry=2027-03-01
```

### Or pass a JSON payload with secret and metadata via STDIN:

```console
$ echo '{"secret":"my-secret-password","metadata":{"owner":"alice"}}' | docker pass set POSTGRES_PASSWORD
```

### Overwrite an existing secret:

```console
$ docker pass set POSTGRES_PASSWORD=new-secret-password --force
```
