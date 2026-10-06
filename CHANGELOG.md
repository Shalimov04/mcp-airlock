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
* **Upstream failures.** An unreachable upstream, a compressed answer or a reply that is not a
  JSON-RPC object used to come back as a synthetic 502 audited as `allow` with no detail. A tool
  call now gets a tool error with rule `upstream.unreachable`, `upstream.encoded` or
  `upstream.bad_reply`, saying whether the call may have run, with verdict `error` in `_meta`
  (`upstream.too_large` too), and the outcome record says `error` with the reason. When the
  connection itself failed, the blast-radius charge is given back, stamped with the charge's own
  time so the two leave the window together; the key of a confirmed `L2` call stays burned and
  the error says to ask again. `tools/list` and `server/discover` still answer 502.
* An SSE answer is reduced to the response carrying the call's id. A stream with only
  notifications, a server-to-client request or a response to another id used to be passed back as
  the answer (HTTP 200, `id: null`), on which the official SDK client hangs; it is now
  `upstream.bad_reply`. `airlock-policy diff` refuses such a catalog too.

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
  request (with libpq 17 or newer), so a replica is meant to hold no more than its pool size of
  backends.
* The Postgres store creates its tables again when they are gone (a database recreated empty)
  instead of failing every gated call with 500 until a restart, and `/readyz` checks that they
  exist and reports 503 while they cannot be created. Confirmation keys already used are
  forgotten when the tables are recreated.
* A torn last line in `audit.jsonl` (a crash or a full disk cut a record short) no longer makes
  every later `airlock-audit verify` fail with `not JSON`: at startup the proxy moves the fragment
  to `audit.jsonl.torn`, cuts the file back to the last newline and logs a warning, and a short
  write it notices itself is cut back at once. A line an older version already kept this way still
  fails `verify`; deleting that line by hand restores the chain, since the record after it chains
  to the one before.
* `airlock-audit query` no longer dies with a JSONDecodeError on a record whose argument holds
  U+2028, U+2029, U+0085 or a few control characters (it split the file the way `str.splitlines`
  does), nor on a torn line: such a line is skipped with `airlock-audit: skipped <file>:<n>: not
  JSON` (or `not a record`, for JSON that is not an object) on stderr and the rest of the log is
  read.
* `airlock-audit query` prints one `airlock-audit: ...` line and exits 1, instead of a traceback,
  for a missing file, a DSN that does not parse (the old traceback quoted part of it, password
  included), an unreachable Postgres or a missing `postgres` extra. A Postgres error keeps
  libpq's words, but every value from the DSN other than a number or a setting such as `sslmode`
  (host, socket path, user, database, password) is blanked to `"..."`, quoted by libpq or not: a
  URI password with an unescaped `@` is parsed with its tail as the host, which libpq's text used
  to show. The Postgres connect has the proxy's connect timeout; `--since 99999999999d` is a
  usage error instead of an OverflowError; `--limit` must be positive (a negative value used to
  drop the oldest N records).
* The Postgres store and audit sink now connect with a 10 second `connect_timeout` (override with
  `AIRLOCK_STORE_CONNECT_TIMEOUT`, at most 86400, or set it in the DSN), plus `tcp_user_timeout`
  (the same value) and TCP keepalives unless the DSN sets them. A black-holed database host used to
  stall every gated call for about two minutes. A `service=` DSN is left unchanged.
* A lone surrogate in client text (JSON allows `"\ud800"`) no longer breaks the audit write; it is
  stored as U+FFFD.
* `airlock-audit query` reads the rotated files too, oldest first.
* A lone surrogate in the request id, in an upstream answer (a result, an error, an SSE frame or a
  tool description) or in the arguments of an `L2` call no longer turns the response into a bare
  HTTP 500 after the upstream already acted. The answer is sent with the JSON escape, the approval
  prompt and the webhook text carry U+FFFD, and the call keeps one outcome record.
* `NaN`, `Infinity` and numbers that overflow a double (`1e400`) in the request body are refused
  with a parse error instead of being forwarded, written to `audit.jsonl` as non-JSON and dropped
  by the Postgres sink. A body nested deeper than 64 levels is refused with `-32600`; one too deep
  to parse at all is a parse error. Both used to be an unaudited bare 500.
* The upstream's answer is read with the same strictness: a reply or an SSE frame holding `NaN`
  (what Python's `json.dumps` emits for a NaN float), `Infinity` or `1e400`, or nested too deep to
  parse, is `upstream.bad_reply`. It used to be an HTTP 500 after the call ran, with a second
  outcome record `internal.error` next to the `allow`.
* `io.mcp-airlock/*` keys that the upstream puts into a result's `_meta`, into a content block's,
  into the dry-run preview or into a `tools/list` answer and each tool in it are removed before
  the proxy adds its own. An upstream could otherwise show the client `status: approved`, an
  empty `suspicious` list or another principal.
* A request refused before it has a principal is audited without its arguments, and its `method`
  and `tool` are cut at 128 characters. Two records of up to the request limit each let an
  unauthenticated client fill the disk or, with rotation on, push the whole real history out of
  the kept files; a 900 KB tool name did the same through the two name fields.
* The `airlock.*` span attributes follow the outcome record. A blocked replay, a decline, a
  `catalog.unavailable` denial or an upstream failure used to leave the span saying what the first
  decision was (or nothing at all); a span whose verdict is `error` now also has status `ERROR`.
* A `traceparent`, `tracestate` or `baggage` in `_meta` that is not a string is ignored and a new
  trace is started, instead of an unaudited bare 500 for any caller. `traceparent` and
  `tracestate` are rebuilt from the span's context before the call is forwarded; a string
  `baggage` is passed on as the client sent it.
* A store that does not answer (a pool timeout, a cut connection, a closed store) now denies the
  gated call with rule `store.unavailable`, as the README said it would: a tool error, an intent
  and an outcome record saying `deny` with the store's error in `detail`, and one warning line in
  the log. It used to be an HTTP 500 `internal error` with a traceback and no intent record. A
  store that answers with a complaint (a bad value, a missing table) is still an internal error,
  since retrying does not cure it.
* A `where` regex can no longer freeze the proxy. A pattern that can take exponential time on a
  crafted value (a repetition inside a repetition such as `(a+)+` or `(.*a){12}`, an alternation
  inside a repetition whose alternatives can start alike, a backreference) is refused when the
  policy loads and by `airlock-policy lint`, and so is one with three or more unbounded repeats
  in a row that can take each other's characters (`.*-.*-.*-prod`: about a second on a
  1024-character value, tens of seconds for four repeats); a regex is tried only on strings up to
  1024 characters, and a longer value fails the rule. `lint` warns about two such repeats in a
  row (`where_regex_cost`, milliseconds at the cap). The README lists the safe patterns the check
  refuses anyway and how to rewrite them. If Python has neither `re._parser` nor `sre_parse`, the
  policy fails to load instead of skipping the check. One `get_service` call with a 32-character
  name used to block the event loop, `/healthz` and `SIGTERM` for over a minute.
* Span attributes and the span name that carry client-chosen text (`gen_ai.tool.name`,
  `gen_ai.tool.call.id`, `rpc.method`, `enduser.id`) go through the same credential scrub as the
  audit `detail`, so a key-shaped tool name or principal no longer reaches the trace backend, and
  they are cut at 128 characters. Patterns added to the scrub later apply to spans as well.
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
