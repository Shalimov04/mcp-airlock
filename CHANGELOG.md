# Changelog

## Unreleased

### Changed

* The Postgres store uses a connection pool (`AIRLOCK_STORE_POOL_SIZE`, default 4) that opens on
  first use and closes at shutdown, instead of a connection per call. The `postgres` extra now
  includes psycopg-pool. A failed connect is given up after the connect timeout, so the store
  recovers within seconds of the database coming back. A store call waits for a pooled connection no
  longer than the connect timeout in the final DSN, work on a connection is cut off after the same
  time (a server that stops answering cannot hang a call), and a call after shutdown is refused. A
  policy that fails validation, a bad DSN or a bad store setting exits with an error message instead
  of a traceback.
* **Pin format.** The tool pin hash now covers `title`, and pins are written as `sha256v2:<hex>`.
  A pins file in the old `sha256:` format is refused: `mcp-airlock` stops at startup, `airlock-policy
  diff --pins` reports it once, and a `SIGHUP` reload keeps the current pins. Run `airlock-policy
  pin` again to rewrite the file. The `catalog.pin_mismatch` audit detail and the `diff` message now
  read "definition changed since it was pinned". Icons and `_meta` are deliberately not covered.
* **Titles in the guard.** The `tools/list` scan for injection phrases now also reads the tool
  `title` and `annotations.title`, not only the description; a hit is marked in `_meta` as before.

### Added

* OTLP span export over HTTP when `OTEL_EXPORTER_OTLP_ENDPOINT` or
  `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` is set. It is the `otlp` extra and the container image
  includes it. Queued spans are flushed on shutdown, and a missing extra is a startup warning
  (an error under `--strict`), not an exit (thanks @HarshRajSinghania, #4).
* Helm chart in `charts/mcp-airlock/`: Deployment, Service, a ConfigMap for the policy, the keys in
  a Secret, a hardened security context and probes on `/healthz` and `/readyz`. It refuses more
  than one replica without a shared store, uses `Recreate` with a persistent `dataVolume` so two
  pods never share one audit hash chain, and refuses such a volume with several replicas.
* `docs/clients.md` has a table of MCP clients and whether they handle the `input_required`
  confirmation (#22). The Python SDK client 2.2.0 is tested (`examples/sdk_client_confirm.py`,
  `tests/test_sdk_client.py`); Claude Code, Cursor and the TypeScript SDK are not tested yet.
* `HEALTHCHECK` in the container image and the demo image: python asks `/healthz` on port 9000,
  bypassing any `HTTP_PROXY`. e2e services that reuse the image for something else disable it.

### Fixed

* The Postgres store and audit sink now connect with a 10 second `connect_timeout` (override with
  `AIRLOCK_STORE_CONNECT_TIMEOUT`, at most 86400, or set it in the DSN), plus `tcp_user_timeout`
  (the same value) and TCP keepalives unless the DSN sets them. A black-holed database host used to
  stall every gated call for about two minutes. A `service=` DSN is left unchanged.
* A lone surrogate in client text (JSON allows `"\ud800"`) no longer breaks the audit write; it is
  stored as U+FFFD.
* `airlock-audit query` reads the rotated files too, oldest first.
* `OTEL_SERVICE_NAME` and `service.name` in `OTEL_RESOURCE_ATTRIBUTES` are honoured; the
  default stays `mcp-airlock`.
* The approver of an out-of-band confirmation is recorded as `verified` only when the identity
  came out of a bearer token the proxy checked. A `Basic` header, a bare value or a bearer with no
  JWT configured used to label the header-supplied name `verified`.
* A JWT whose `sub` is empty or blank is refused with 401 `principal.missing` instead of being
  accepted as principal `""`; a blank `X-Airlock-Principal` is refused the same way.

## 0.3.0 - 2026-10-02

### Changed

* **Approval mode.** `AIRLOCK_APPROVAL_MODE` is `oob` by default when an approval webhook is
  configured: a confirmation is approved on the page the webhook delivers, not by the agent
  replaying the token. Set `inband` to keep the old behaviour. The mode is carried in the token, and
  the stricter one wins when replicas disagree.
* The upstream is asked for an uncompressed answer (`Accept-Encoding: identity`). A compressed
  answer is refused with a 502, because compression would defeat the size bound.
* Audit records have two more keys, `prev` and `hash`.
* psycopg is now the `postgres` extra: `pip install 'mcp-airlock[postgres]'`. A DSN without it stops
  startup with that hint. The container image includes it. `mcp` is bounded below 3.

### Added

* Approve page shows the redacted arguments and the dry-run preview. New table `airlock_prompts`
  holds the text when `AIRLOCK_STORE_DSN` is set; it is created on first use.
* `where` conditions in the policy: allow or refuse by argument values.
* Tool pins (`airlock-policy pin`, `--pins`, `AIRLOCK_PINS`): a tool whose description or schema
  changed is flagged and refused.
* `/healthz` and `/readyz`.
* `AIRLOCK_MAX_REQUEST_BYTES` (413) and `AIRLOCK_MAX_UPSTREAM_BYTES`.
* Startup warnings for configurations that are weaker than they look, and `--strict` to exit with
  status 2 on any of them.
* SIGHUP reloads the policy file and the pins file as one pair; a file that does not load keeps
  the current policy.
* `--audit-max-bytes` and `--audit-keep` rotate the audit file. `airlock-audit verify` checks the
  hash chain across the rotated files.
* Nightly and on-demand e2e workflow for the postgres and grafana stacks; ruff in CI; CI runs the
  suite against the lowest and the newest allowed dependency versions.

### Fixed

* The approval webhook URL is no longer logged when delivery fails.
* The audit `detail` field is redacted like the arguments.
* `count_arg` counts a JSON-encoded list or object by its elements. A string the proxy cannot
  decode is refused with `blast_radius.per_call` instead of counting as one.
* `demo.py` was a syntax error on Python 3.11.

### Release process

* The release workflow runs the tests first, pins every action by commit SHA, and checks that
  `pyproject.toml` and `server.json` carry the tag version. Dependabot keeps the pins current.

## 0.2.0 - 2026-09-16

* PostgreSQL example policy (bettyguo/mcp-postgres).
* End-to-end stacks against real MCP servers (kubernetes, grafana, postgres), policies for Grafana
  and Kubernetes corrected against live catalogs.
* SECURITY.md, demo container, release tooling (CI, PyPI and ghcr publishing, registry manifest).

## 0.1.0 - 2026-09-14

* First release: allowlist, forced dry run, human confirmation, blast radius, audit, tracing.
