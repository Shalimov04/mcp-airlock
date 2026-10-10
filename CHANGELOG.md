# Changelog

## Unreleased

### Fixed

* The documented worst case of a `where` regex at the 4096-character cap is about 0.13 s for ASCII
  and about 0.3 s for 4-byte characters (RE2 costs per byte); the cap itself is unchanged.

## 0.4.0 - 2026-10-10

### Breaking

* **`where` regexes use RE2.** A `where` regex could freeze the proxy: one `get_service` call with
  a 32-character name blocked the event loop, `/healthz` and `SIGTERM` for over a minute. A `regex`
  rule is now matched with google-re2, in time linear in the value length, and only on strings up
  to 4096 characters; a longer value fails the rule (fails closed). google-re2 is the optional
  extra `regex` (`pip install 'mcp-airlock[regex]'`, included in the Docker image); a policy with
  a `regex` rule does not load without it and says so.
  * Patterns 0.3.0 accepted can now fail to load (a startup error, `ERROR invalid` in
    `airlock-policy lint`, a `SIGHUP` reload keeps the current policy): lookahead and lookbehind,
    backreferences, possessive and atomic groups, `\Z` (write `\z`), `\uXXXX` (write `\x{41}`),
    `\N{...}`, `(?x)`, `(?#...)`, `(?a)`, `(?u)` and a counted repeat above 1000. `a{,3}` loads but
    means the literal text (write `a{0,3}`).
  * Matching changes both ways: `\w`, `\d`, `\s` and `\b` are ASCII-only, so they deny more
    (`\w+` no longer matches `привет`; use `\pL`), while `\W`, `\D`, `\S` and `\B` match non-ASCII
    characters and admit more (`\W+` now matches `привет`). A value with a lone surrogate fails a
    `regex` rule.
* **Pin format.** The tool pin hash now covers `title`, and pins are written as `sha256v2:<hex>`.
  A pins file in the old `sha256:` format is refused: `mcp-airlock` stops at startup,
  `airlock-policy diff --pins` reports it, and a `SIGHUP` reload keeps the current pins. Run
  `airlock-policy pin` again. Icons and `_meta` are deliberately not covered.
* The Python `Airlock` class no longer takes the legacy `trust_principal_header` and `jwt_secret`
  arguments; pass an `IdentityConfig`.

### Added

* OTLP span export over HTTP when `OTEL_EXPORTER_OTLP_ENDPOINT` or
  `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` is set (the `otlp` extra, included in the image). Spans are
  flushed on shutdown; a missing extra is a startup warning, an error under `--strict` (thanks
  @HarshRajSinghania, #4). `OTEL_SERVICE_NAME` and `service.name` are honoured.
* Helm chart in `charts/mcp-airlock/`: Deployment, Service, policy ConfigMap, a Secret for the keys,
  hardened security context, probes on `/healthz` and `/readyz`. It refuses several replicas without
  a shared store, uses `Recreate` with a persistent `dataVolume` so two pods never share one audit
  chain, sleeps `preStopSeconds` (5) before shutdown so a rolling update refuses no connections, and
  refuses credentials such as `OTEL_EXPORTER_OTLP_HEADERS` in `env` (they go in `existingSecret`,
  `extraEnv` or `envFrom`). A `values.schema.json` rejects wrong types (a fraction or a `null` in
  `env`, for example).
* The Postgres store uses a connection pool (`AIRLOCK_STORE_POOL_SIZE`, default 4; the `postgres`
  extra now includes psycopg-pool). Store and audit connections get a 10 second connect timeout
  (`AIRLOCK_STORE_CONNECT_TIMEOUT`), `tcp_user_timeout` and TCP keepalives, and server-side
  `statement_timeout` and `lock_timeout`, so a black-holed database no longer stalls gated calls for
  minutes or leaves backends behind. A store that does not answer denies the gated call with rule
  `store.unavailable` (it was an HTTP 500 with no intent record). The tables are created again if
  the database is recreated empty (confirmation keys already used are forgotten then), and `/readyz`
  is 503 until they exist.
* `HEALTHCHECK` in the container images (python asks `/healthz`, ignoring `HTTP_PROXY`).
* `docs/clients.md` lists which MCP clients handle the `input_required` confirmation (#22); the
  Python SDK client 2.2.0 and 2.3.0 are tested.
* The `tools/list` scan for injection phrases also reads the tool `title` and `annotations.title`.
* `airlock-audit query` reads the rotated files too, oldest first.
* Startup warnings (errors under `--strict`) for `AIRLOCK_SECRET` without `AIRLOCK_STORE_DSN` (a
  fixed key with the memory store let a confirmed call run again on another replica or after a
  restart), for an approval webhook that is not an `http(s)` URL, and for a Telegram URL and chat id
  that do not go together.

### Changed

* **Upstream failures.** An unreachable upstream, a compressed answer or a reply that is not a
  JSON-RPC object used to come back as a synthetic 502 audited as `allow`. A tool call now gets a
  tool error with rule `upstream.unreachable`, `upstream.encoded`, `upstream.bad_reply` or
  `upstream.too_large`, verdict `error`, saying whether the call may have run. When the connection
  itself failed the blast-radius charge is given back; a confirmed `L2` key stays burned and the
  agent asks again. `tools/list` and `server/discover` still answer 502.
* An SSE answer is reduced to the response carrying the call's id; a stream without it is
  `upstream.bad_reply` (the official SDK client used to hang on it).
* The request and the upstream answer must be strict JSON: `NaN`, `Infinity`, numbers that
  overflow a double (`1e400`) and nesting over 64 levels are refused (`-32700` or `-32600` for the
  request, `upstream.bad_reply` for the answer) instead of being forwarded and breaking the audit.
* `--otel-file` writes JSON Lines, one span per line. `airlock-policy diff` and `pin` read
  `AIRLOCK_ENV` when `--env` is not given, as the proxy does.
* `mcp-airlock`, `airlock-policy` and `airlock-audit` report a missing or invalid policy, an
  unopenable file, a bad DSN or setting and an unreachable Postgres as one line instead of a
  traceback (`AIRLOCK_DEBUG=1` keeps it). Credentials from a DSN are blanked in those messages.
* The Postgres audit sink is a mirror of the file: the same `prev` and `hash`, written from a
  worker thread through a bounded queue (1000 records, about 32 MiB). A record that fails or finds
  the queue full is dropped from the table with a warning; the JSONL file keeps it and is the one
  to verify. The table's `intent` row can land after the upstream call; the file's is still written
  first. At shutdown the queue is drained for about the connect timeout, then the rest is dropped
  and counted in the log. The table is created under the store's advisory lock, so replicas
  starting together lose no records.
* A confirmation token from before 0.3.0 (no approval mode in it) counts as `oob`: an inband
  replica no longer accepts it in-band, so it stays pending until approved by link or it expires
  (10 minutes).

### Fixed

* **Audit.** With `AIRLOCK_AUDIT_DSN` set, a failed write to `audit.jsonl` (a full disk, EIO) was
  logged and the call forwarded with no intent record in the file. The intent write now fails
  closed, as it does without the DSN: the table still gets the record and the `internal.error`
  outcome, and the caller gets an error (#79, #80).
* A torn last line in `audit.jsonl` no longer makes every later `airlock-audit verify` fail: at
  startup the proxy moves the fragment to `audit.jsonl.torn` and cuts the file back to the last
  newline. A torn line an older version kept still fails `verify`; delete it by hand.
* `airlock-audit query` no longer dies on a record containing U+2028, U+2029 or U+0085, or on a
  torn line (it is skipped with a note on stderr), and `--limit` rejects a negative value.
* A lone surrogate or NUL in client text, a `NaN` and an infinity no longer break the audit write
  or turn a response into a bare HTTP 500 after the upstream acted; they are stored as U+FFFD or as
  a string, the same in both sinks.
* **Redaction.** Credentials inside longer argument strings and in argument keys are redacted in
  the audit `args` and in the arguments shown to approvers, matched only at the start of a word so
  `disk-cleanup-prod` is kept. The `principal`, `method` and `tool` fields, the keys in `detail` and
  span attributes with client text are scrubbed too.
* A request refused before it has a principal is audited without its arguments, and its `method`
  and `tool` are cut at 128 characters; an unauthenticated client could fill the disk or push the
  real history out of the rotated files.
* `io.mcp-airlock/*` keys that the upstream puts into `_meta` (results, content blocks, previews,
  `tools/list`) are removed before the proxy adds its own, so an upstream cannot fake `status:
  approved` or an empty `suspicious` list.
* **Approvals.** The approver is recorded as `verified` only when the identity came from a bearer
  token the proxy checked. A JWT with an empty or blank `sub`, a blank `X-Airlock-Principal`, or a
  name with surrounding whitespace, is refused with 401 `principal.missing`. A principal named
  `group:<g>` no longer gets the tier override of group `<g>`.
* The Slack message escapes `&`, `<` and `>` in the arguments and the preview, and cuts its text at
  3500 characters so the proxy's `Approve:` line is always delivered and always last. The approve
  page is sent with `Cache-Control: no-store`, `Referrer-Policy`, `X-Frame-Options`,
  `X-Content-Type-Options` and a Content-Security-Policy that forbids framing. A failure while
  working out who clicked is recorded as unverified instead of a bare 500.
* A `tools/call` retried with the `requestState` of a confirmation already executed or declined is
  refused with `mrtr.replay` instead of staying `pending`. A `POST` on such an approve link answers
  409 and records nothing; a second `POST` on an approved one changes nothing. A pending result
  carries `verdict: confirm` and `rule_id: mrtr.pending` in `_meta`.
* An `L2` call whose dry-run preview was longer than `output.max_chars` and had `structuredContent`
  came back as a truncated error instead of a confirmation prompt. The prompt is now issued from
  the trimmed preview; only the upstream's own `isError` skips it.
* A `traceparent`, `tracestate` or `baggage` in `_meta` that is not a string is ignored instead of
  causing an unaudited 500. The `airlock.*` span attributes follow the outcome record, and a span
  with verdict `error` has status `ERROR`.
* An OTLP timeout that is not a number, or a compression other than `none`, `gzip` or `deflate`,
  stops the start with one error line again (OpenTelemetry 1.45 only logs it).
* `airlock-policy lint` accepts a policy without `environment` when `--env` or `AIRLOCK_ENV` names
  one, and `diff` and `pin` report an invalid policy or a bad `tools/list` answer as `ERROR`
  lines instead of a traceback.
* Helm: a whole number from a values file rendered as `1.048576e+08` and crash-looped the pod.
* The release workflow file was invalid YAML, so a `v*` tag would not have released; it is fixed
  and tested. The release also fails when the `docker run` image tag in the READMEs is not the
  tag's major.minor. The nightly Postgres e2e stack works again with the image `HEALTHCHECK`.
* The container images compile bytecode at build time (the filesystem is read-only at run time, so
  every start paid the import cost).
* The README `docker run` example adds `--add-host=host.docker.internal:host-gateway` (Docker
  Engine on Linux cannot resolve the upstream host without it), `docs/clients.md` uses `claude mcp
  add --scope user`, and `policy.example.yaml` no longer says `restart_service` is refused at L2.

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
  changed is dropped from `tools/list` and audited as `catalog.pin_mismatch`. A call to it is
  still decided by the policy.
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
