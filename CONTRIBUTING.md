# Contributing

## Setup

```
uv sync --frozen
uv run pytest -q
uv run ruff check .
```

Set `AIRLOCK_TEST_PG_DSN` to a Postgres DSN to also run the Postgres tests (without it they are
skipped):

```
docker run -d -e POSTGRES_PASSWORD=airlock -e POSTGRES_USER=airlock -p 5432:5432 postgres:16-alpine
export AIRLOCK_TEST_PG_DSN=postgresql://airlock:airlock@127.0.0.1:5432/airlock
```

## Before a pull request

* A change to behaviour comes with a test that fails without it.
* A change that touches the proxy path, the store, the audit log or the approval flow should also
  pass `e2e/postgres/run.sh` (needs Docker). `e2e/grafana/run.sh` covers the Grafana policy.
* Update `README.md` and `README.ru.md` together, and add a line to `CHANGELOG.md`.
* CI runs the suite on Python 3.11 to 3.13, against the lowest and newest allowed dependency
  versions, and ruff.

## Style

* Keep comments short and about why, not what.
* Plain ASCII punctuation in code and docs: no em-dashes, no arrows.

## Reporting a vulnerability

See [SECURITY.md](SECURITY.md). Do not open a public issue for one.
