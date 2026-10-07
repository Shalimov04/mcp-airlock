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
* Helm: `OTEL_EXPORTER_OTLP_HEADERS` is read from `existingSecret` like the other credentials and
  refused in `env`; new `extraEnv` (with `valueFrom`) and `envFrom` values take entries from a
  Secret or ConfigMap of your own. An `extraEnv` name that is also in `env`, or that is
  `AIRLOCK_STORE_DSN` or `AIRLOCK_SECRET` with `sharedStore`, is refused at render time instead
  of being set twice in the container, which server-side apply rejects; a non-string `value` in
  `extraEnv` is refused too.
* Helm: the pod sleeps `preStopSeconds` (5) before shutting down, so a rolling update, including
  every policy change, no longer refuses connections; `terminationGracePeriodSeconds` (30) is set
  for the sleep, the open calls and the OTLP flush. A negative or fractional value, or the sleep
  on a cluster older than 1.30 (set `preStopSeconds=0` there), is refused with a chart message.

### Fixed

* The release workflow fails when the image tag in the `docker run` examples of `README.md` and
  `README.ru.md` is not the tag's major.minor (`scripts/check_image_tag.sh`).
* Helm: a whole number from a values file (`env.AIRLOCK_MAX_REQUEST_BYTES: 104857600`, or in
  `extraArgs`) rendered as `1.048576e+08` and crash-looped the pod; it now renders as `104857600`.
* The container images compile bytecode at build time (`UV_COMPILE_BYTECODE=1` for the venv,
  `compileall` for the standard library, which the slim base image ships without `.pyc`); the
  filesystem is read-only at run time, so no `.pyc` could ever be written and every start paid
  the import cost.
* `policy.example.yaml` no longer tells approvers that `restart_service` is refused at L2: a tool
  without `dry_run` is refused at L1 and confirmed without a preview at L2.
* The README `docker run` example adds `--add-host=host.docker.internal:host-gateway`, without
  which Docker Engine on Linux cannot resolve the upstream host.
* `docs/clients.md`: the `claude mcp add` command gets `--scope user`; without it the server is
  registered for the current project only.
* `AIRLOCK_SECRET` without `AIRLOCK_STORE_DSN` is a startup warning (an error under `--strict`):
  the memory store remembers a used confirmation only in its own process, so a fixed key let a
  confirmed call run again on a second replica or after a restart. The README told you to set
  the key for replicas without saying that it needs the shared store.
* A store query that waited on a lock kept its server backend after the client gave up on it, so
  one replica could use up `max_connections`. Pooled connections now get `statement_timeout` and
  `lock_timeout` just under the connect timeout in force, and a cut connection also sends a cancel
  request (with libpq 17 or newer), so a replica is meant to hold no more than its pool size of backends.
* The Postgres store creates its tables again when they are gone (a database recreated empty)
  instead of failing every gated call with 500 until a restart, and `/readyz` checks that they
  exist and reports 503 while they cannot be created. Confirmation keys already used are
  forgotten when the tables are recreated.
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
  accepted as principal `""`; a blank `X-Airlock-Principal` is refused the same way. So is a name
  with surrounding whitespace, from either source: trimmed, `alice ` would be `alice`.
* The Slack approval message escapes `&`, `<` and `>` in the arguments and the dry-run preview, so
  an agent cannot plant a `<url|label>` link or an `<!channel>` mention in it.
* The text of the approval message is cut at 3500 characters, with a note, before the proxy's
  `Approve:` line is added, so the line is always delivered and always last: Telegram refuses a
  longer message, and Slack truncates one, which an oversized argument could use to cut the real
  line off behind a planted one. The approve page's cut note now points at the audit record.
* A failure while working out who clicked the approve button (after the approval was recorded)
  records the click as unverified instead of answering a bare 500 that the audit never sees.
* A principal named `group:<g>` no longer gets the tier override of group `<g>`: `group:` keys in
  `principals` match group membership only.
* The approve page responses carry `Cache-Control: no-store`, `Referrer-Policy: no-referrer`,
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and a Content-Security-Policy with
  `frame-ancestors 'none'`.
* A `tools/call` retried with a `requestState` whose confirmation was already executed or declined,
  and no answer, is refused with `mrtr.replay` instead of staying `pending` until the token
  expires. In `inband` mode without a webhook such a retry gets the question again with a fresh
  `requestState`, since there is nothing to wait for.
* The `pending` result carries `verdict: confirm` and `rule_id: mrtr.pending` in `_meta`, like
  every other `tools/call` result, and its message says when an in-band accept was ignored.
* `POST` on an approve link whose confirmation was already executed or declined answers 409 and
  records nothing; it used to say "Approved" and write `mrtr.approved_oob`. A second `POST` on an
  approved confirmation changes nothing and is not recorded again, and the page shows the state.
  A store that does not answer during the `POST` gives 503 with the page's headers, not a bare 500.
* A startup warning (an error under `--strict`) for an `AIRLOCK_APPROVAL_WEBHOOK` that is not an
  `http(s)` URL with a host, for a Telegram URL without `AIRLOCK_TELEGRAM_CHAT`, and for a chat id
  without a webhook. Such a proxy used to start in `oob` mode with nothing able to approve.

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
