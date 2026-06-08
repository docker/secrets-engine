# Releasing modules

This repository is a multi-module Go repository. Each module is released with
its own tag of the form `<module>/vX.Y.Z` (for example `store/v0.0.29`).

Releases are cut with the helper in [`x/release`](../x/release):

```sh
# from the repository root
go run ./x/release bump <module>
```

By default this performs a patch release and propagates the bump to internal
downstream modules. Useful flags:

- `--release <patch|minor|major>` — choose the bump level for `<module>`
  (downstreams are always propagated as a patch).
- `--dry` — log every step without changing anything.
- `--skip-git` — preview only the `go.mod` edits, skipping git operations.
- `--no-propagate` — release only `<module>`; do not bump downstreams.

## How a release is applied

For the released module the tool:

1. Creates an annotated tag on the current `HEAD` and pushes the tag.
2. Bumps the module version in each downstream `go.mod`.
3. Commits those edits as `chore: bump <module>/vX.Y.Z`.

> [!IMPORTANT]
> The tag is created on `HEAD`, and the `chore: bump` commit is committed
> **locally** — the tool pushes tags, not the branch. Land that commit on the
> default branch via a PR.

## HEAD must match the remote default branch

Before creating any tag, the tool fetches and verifies that `HEAD` is exactly
the tip of the remote default branch (`origin/HEAD`, falling back to `main`).
If it is not, the release is refused:

```
refusing to tag: HEAD (<sha>) is not at the tip of origin/main (<sha>); ...
```

This guard exists because the tool tags whatever `HEAD` points at. If it is run
while `HEAD` sits on a local-only `chore: bump` commit (or any commit not yet on
the default branch), the tag lands on a commit that does not contain changes
merged afterwards. That is exactly how `store/v0.0.28` was pinned to an older
`chore: bump store/v0.0.27` commit and shipped without a keychain fix that had
already merged via PRs.

Always release from an up-to-date checkout of the default branch:

```sh
git checkout main
git pull --ff-only
go run ./x/release bump <module>
```

The `--dry` and `--skip-git` modes skip this check, since they do not create
tags.
