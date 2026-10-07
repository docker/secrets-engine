### Type or paste the value at the prompt:

```console
$ docker pass set POSTGRES_PASSWORD
Enter secret for POSTGRES_PASSWORD: ******************
```

### Pipe the value from another command:

```console
$ printf '%s' my-secret-password | docker pass set POSTGRES_PASSWORD
```

### Read a multi-line value from a file:

```console
$ docker pass set my-cert < cert.pem
```

### Pass the value inline:

```console
$ docker pass set POSTGRES_PASSWORD=my-secret-password
```

### Attach metadata:

```console
$ docker pass set POSTGRES_PASSWORD --metadata owner=alice --metadata expiry=2027-03-01
Enter secret for POSTGRES_PASSWORD: ******************
```

### Pipe value and metadata as JSON:

```console
$ echo '{"secret":"my-secret-password","metadata":{"owner":"alice"}}' | docker pass set POSTGRES_PASSWORD
```

### Overwrite an existing secret:

```console
$ docker pass set POSTGRES_PASSWORD --force
Enter secret for POSTGRES_PASSWORD: ******************
```
