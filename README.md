# Cloud AI Control Verifier

Cloud AI Control Verifier (`cai-verify`) is an AWS-first, open-source tool for
executing focused security-control tests against deployed AI applications and
producing machine-readable evidence.

This repository currently contains the Python project scaffold and version
command only. It does not implement control tests or establish HIPAA, FedRAMP,
NIST, or legal compliance.

## Requirements

- [uv](https://docs.astral.sh/uv/) 0.11.19 or a compatible 0.11 release
- GNU Make
- Python 3.14 (uv can install the version selected by `.python-version`)

## Local setup

Create the development environment and install the project:

```console
uv sync --all-extras --dev
```

Run the CLI in the managed environment:

```console
uv run cai-verify version
```

To invoke `cai-verify` directly, activate the environment first:

```console
source .venv/bin/activate
cai-verify version
```

Run the complete local quality gate:

```console
make check
```

The test configuration disables socket access, so unit tests cannot reach the
network or AWS.

## Development commands

| Command          | Purpose                                              |
| ---------------- | ---------------------------------------------------- |
| `make format`    | Format Python and Markdown and apply safe Ruff fixes |
| `make lint`      | Check Python formatting and lint rules               |
| `make typecheck` | Run mypy in strict mode                              |
| `make test`      | Run pytest with network access disabled              |
| `make docs`      | Check Markdown formatting                            |
| `make build`     | Build and validate the source and wheel artifacts    |
| `make audit`     | Audit locked dependencies for known vulnerabilities  |
| `make check`     | Run lint, types, tests, docs, and package validation |


## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
