# Changelog

## Unreleased

### Added

* Helm chart in `charts/mcp-airlock/`: Deployment, Service, a ConfigMap for the policy, the keys in
  a Secret, a hardened security context and probes on `/healthz` and `/readyz`. It refuses more
  than one replica without a shared store, uses `Recreate` with a persistent `dataVolume` so two
  pods never share one audit hash chain, and refuses such a volume with several replicas.

### Fixed

* A lone surrogate in client text (JSON allows `"\ud800"`) no longer breaks the audit write; it is
  stored as U+FFFD.
* `airlock-audit query` reads the rotated files too, oldest first.

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
