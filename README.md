

```console
# Build the secrets plugin
go build ./cmd/docker-secrets

# Run the local secrets store
./docker-secrets serve --socket api.sock

# Now, run a container with the the socket bind mounted
docker run --rm -it -v $PWD/api.sock:/run/secrets/api.sock debian

# Install curl in the container
root@1d06e3a52cf6:/# apt update && apt install curl
...

# Now, try to access the secrets
root@1d06e3a52cf6:/# curl --unix-socket /run/secrets/api.sock http://localhost/secrets/resolve\?id\=foo/bar\&id\=foo/baz | jq .
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   202  100   202    0     0   4971      0 --:--:-- --:--:-- --:--:--  5050
{
  "Secrets": [
    {
      "ID": "foo/bar",
      "Error": "secret foo/bar not available: secret \"foo/bar\": secret not found"
    },
    {
      "ID": "foo/baz",
      "Error": "secret foo/baz not available: secret \"foo/baz\": secret not found"
    }
  ]
}

# Oh no! They're not there! Let's create them. In another terminaal, create the secrets:
# echo asdf | ./docker-secrets set foo/bar -
# echo asdf | ./docker-secrets set foo/baz -

# Now try from the container again
root@1d06e3a52cf6:/# curl --unix-socket /run/secrets/api.sock http://localhost/secrets/resolve\?id\=foo/bar\&id\=foo/baz | jq .
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   289  100   289    0     0  12264      0 --:--:-- --:--:-- --:--:-- 12565
{
  "Secrets": [
    {
      "ID": "foo/bar",
      "Value": "YXNkZgo=",
      "Provider": "local",
      "CreatedAt": "2025-05-05T17:55:36-07:00",
      "ResolvedAt": "2025-05-06T00:55:41.47793Z"
    },
    {
      "ID": "foo/baz",
      "Value": "YXNkZgo=",
      "Provider": "local",
      "CreatedAt": "2025-05-05T17:55:39-07:00",
      "ResolvedAt": "2025-05-06T00:55:41.481284Z"
    }
  ]
}

# Cool!
```
