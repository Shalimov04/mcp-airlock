# Contributing

## Setup

```
uv sync --frozen --all-extras
uv run pytest -q
uv run ruff check .
```

`--all-extras` installs the `postgres`, `otlp` and `regex` extras; without the `otlp` one the
OTLP tests are skipped. Set `AIRLOCK_TEST_PG_DSN` to a Postgres DSN to also run the Postgres
tests (without it they are skipped):

```
docker run -d -e POSTGRES_PASSWORD=airlock -e POSTGRES_USER=airlock -p 5432:5432 postgres:16-alpine
export AIRLOCK_TEST_PG_DSN=postgresql://airlock:airlock@127.0.0.1:5432/airlock
```

`uv run python demo.py` runs the proxy against the fake upstream and rewrites `examples/audit.jsonl`
and `examples/spans.jsonl`; do not commit those unless the change is the point.

## Before a pull request

* A change to behaviour comes with a test that fails without it.
* A change that touches the proxy path, the store, the audit log or the approval flow should also
  pass `e2e/postgres/run.sh` (needs Docker). `e2e/grafana/run.sh` covers the Grafana policy and
  `e2e/kubernetes/run.sh` the Kubernetes one.
* A change to the chart passes `helm lint charts/mcp-airlock --set upstream=http://x/mcp
  --set-file policy=policy.example.yaml` and renders with `helm template`.
* A change to the Dockerfiles keeps `tests/test_container.py` green: it reads the `HEALTHCHECK`
  lines and runs the probe command.
* A change under `.github/workflows/` keeps `tests/test_workflows.py` green: it parses every
  workflow file and runs the release chart `appVersion` check against the tree.
* Update the docs in the same pull request: `README.md` and `README.ru.md` together, section by
  section (the Russian one is natural Russian prose, not a word-for-word calque), the env var and
  flag tables when a variable or flag changes, `charts/mcp-airlock/values.yaml` comments when a
  value changes, `docs/clients.md` when the client-facing behaviour changes, and a line under
  `Unreleased` in `CHANGELOG.md`.
* CI runs the suite on Python 3.11 to 3.13, against the lowest and newest allowed dependency
  versions, and ruff.

## Style

* Keep comments short and about why, not what.
* Plain ASCII punctuation in code and docs: no em-dashes, no arrows, no smart quotes.
* Docs: lines wrapped at about 100 columns (tables and commands may run longer), short sentences,
  no marketing tone. Say what the proxy does and what it does not.
* Commit messages: an imperative subject line, then a wrapped body that says what changed and why.

## Releasing

A release is a tag `vX.Y.Z` on `main`. Before tagging, bump the version in `pyproject.toml`,
`server.json` (both `version` fields) and `appVersion` in `charts/mcp-airlock/Chart.yaml`, move
the `Unreleased` section of `CHANGELOG.md` under the new version, and update the image tag in the
`docker run` examples of both `README.md` and `README.ru.md` (`:X.Y`). The release workflow checks
the three versions and the two README image tags against the tag (`scripts/check_image_tag.sh`),
runs the tests, publishes to PyPI and pushes the image to ghcr.io tagged `X.Y.Z` and `X.Y`.

## Reporting a vulnerability

See [SECURITY.md](SECURITY.md). Do not open a public issue for one.
