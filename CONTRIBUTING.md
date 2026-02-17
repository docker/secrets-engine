# Contributing to Secrets Engine

Want to contribute to Secrets Engine? Great! Please read this guide first.

## Development Setup

### Prerequisites

- Go (see `go.work` for the required version)
- Docker with Buildx
- Make

### Building

```bash
go build ./...
```

### Testing

Run all unit tests (with race detection):

```bash
make unit-tests
```

### Linting

Linting runs inside Docker via Buildx:

```bash
make lint
```

### Formatting

```bash
make format
```

### Proto Generation

If you modify `.proto` files, regenerate the Go code:

```bash
make proto-generate
```

## Submitting a Pull Request

1. Fork the repository and create your branch from `main`.
2. If you've added code, add tests.
3. Ensure `make lint` and `make unit-tests` pass.
4. Submit your pull request.

## Sign Your Commits (DCO)

This project uses the [Developer Certificate of Origin](https://developercertificate.org/) (DCO).
All commits must be signed off to certify that you have the right to submit the
contribution under the project's license.

Sign off your commits with `git commit -s`:

```
Signed-off-by: Your Name <your.email@example.com>
```

## Reporting Issues

Use [GitHub Issues](https://github.com/docker/secrets-engine/issues) to report bugs or request features.

## Code of Conduct

Participation in this project is governed by the
[Docker Community Guidelines](https://github.com/docker/code-of-conduct).
