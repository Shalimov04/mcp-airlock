# Connecting Claude Code and Cursor through mcp-airlock

The proxy is an ordinary streamable HTTP MCP endpoint, so any client that can talk to a
remote MCP server can talk to it. The only thing a client has to add is identity: the proxy
refuses every call that arrives without a principal.

Start the proxy in front of the server you want to govern. For a laptop setup the simplest
identity is a header, which the proxy only accepts when told to:

```
export AIRLOCK_TRUST_PRINCIPAL_HEADER=1
uvx mcp-airlock --policy policy.yaml --upstream http://127.0.0.1:8080/mcp --env dev
```

Only trust the header on a machine where nobody else can reach port 9000; the proxy listens on
`127.0.0.1` unless you pass `--host`. Anywhere shared, leave the variable unset and give the
client a bearer JWT instead (`AIRLOCK_JWT_SECRET` or `AIRLOCK_JWKS_URL` on the proxy side, see
the README's "Environment variables" table).

## Claude Code

One command, user scope (without `--scope user` Claude Code registers the server for the current
project only):

```
claude mcp add --transport http --scope user github-airlocked http://127.0.0.1:9000/mcp \
  --header "X-Airlock-Principal: alice"
```

Or commit it for the whole team in `.mcp.json` at the project root. Note the `type`; Claude
Code treats an entry with a `url` and no `type` as a misconfigured stdio server:

```json
{
  "mcpServers": {
    "github-airlocked": {
      "type": "http",
      "url": "http://127.0.0.1:9000/mcp",
      "headers": { "Authorization": "Bearer ${AIRLOCK_TOKEN}" }
    }
  }
}
```

`claude mcp get github-airlocked` shows whether it connected. `tools/list` through the
proxy only returns tools that are in the policy and, with a pins file, whose definition
still matches its pin (audited as `catalog.pin_mismatch`), so a tool the agent "cannot
see" is a policy question, not a connection problem. The answer's `_meta` says how many
tools were hidden (`io.mcp-airlock/hidden_tools`) and how many failed their pin
(`io.mcp-airlock/pin_mismatch`).

## Cursor

`.cursor/mcp.json` in the project (or `~/.cursor/mcp.json` for every project):

```json
{
  "mcpServers": {
    "github-airlocked": {
      "url": "http://127.0.0.1:9000/mcp",
      "headers": { "X-Airlock-Principal": "alice" }
    }
  }
}
```

Cursor picks the file up on save; the server appears under MCP in settings with its tool
list.

## What the agent sees

* A tool outside the policy, or over its blast radius, comes back as a tool result with
  `isError: true` and a one-line reason. The model reads it and moves on.
* An `L1` tool always runs with `dry_run: true`, whatever the agent asked for.
* An `L2` tool runs as a dry run first and the result is `input_required`: a description of
  what would happen plus a signed `requestState`. A client that implements the 2026-07-28
  confirmation flow shows that description to you and, when you accept, repeats the call
  with the state; the proxy then runs it for real, once. With an approval webhook the
  accept alone is not enough by default, see the end of this section.

That last point is the one to check before relying on `L2`. The table below records which
clients have been tested; for a client not listed, call an `L2` tool and see whether you get
asked. If the client ignores `input_required`, the model just sees an unusual result and
cannot complete the call; in that case keep such tools at `L3` with a small blast radius, or
at `L1`, until the client catches up. Out-of-band approval through Slack or Telegram does not
remove the need to repeat the call: the agent still has to repeat it with `requestState`
after the button is pressed. With a webhook configured the proxy runs in `oob` mode by
default, so accepting the prompt in the client does not approve anything; the client shows
the prompt, and the person approves through the link. Set `AIRLOCK_APPROVAL_MODE=inband` if
you want the client's accept to approve. The README section "Confirmations in detail" has
the rest.

## Which clients handle the confirmation

Each row records what was observed for one client version on one date. Nothing here is
inferred from vendor documentation.

| Client | Version | Prompt shown to the person | `inputResponses` sent back on accept | Decline stops the call | Tested | Evidence |
|---|---|---|---|---|---|---|
| MCP Python SDK (`mcp.client.Client`) | 2.3.0 (pinned in `uv.lock`), 2.2.0 | Only through the application's `elicitation_callback` [1] | Yes: `{"airlock-confirm": {"action": "accept", "content": {"confirm": true}}}` with the same `requestState`; the call ran once as `tier.L2.confirmed` | Yes: `mrtr.declined` comes back as a tool error; only the dry run reached the upstream | 2026-10-10 | [`examples/sdk_client_confirm.py`](../examples/sdk_client_confirm.py), [`tests/test_sdk_client.py`](../tests/test_sdk_client.py), `e2e/postgres/run.sh` scenarios 04 (accept) and 15 (`oob`) |
| Claude Code | - | not tested yet | not tested yet | not tested yet | - | contributions welcome |
| Cursor | - | not tested yet | not tested yet | not tested yet | - | contributions welcome |
| MCP TypeScript SDK client | - | not tested yet | not tested yet | not tested yet | - | contributions welcome |

1. The SDK has no UI, so what the person sees is whatever the application's callback shows.
   Without a callback the call raises `MCPError` ("Elicitation not supported"), no retry is
   sent and nothing runs; the confirmation key expires unused.
2. The SDK's built-in loop polls a pending answer for about two seconds and then raises
   `InputRequiredRoundsExceededError`. That matters in `oob` mode; see "Confirmations in
   detail" in the [README](../README.md#confirmations-in-detail). Observed in
   `test_python_sdk_in_oob_mode_gives_up_after_a_few_polls_and_never_executes` and in
   e2e scenarios 07 and 15: the accept is ignored, nothing runs for real.
3. `cancel`, and accept with the box unchecked, count as a decline and burn the key.
4. A client that answers accept automatically (an auto-approve setting, or a callback with no
   person behind it) defeats `L2` in `inband` mode. If you cannot be sure a person sees the
   prompt, use `oob` mode with a webhook.

The SDK run in full (`uv run python examples/sdk_client_confirm.py`, stdout):

```text
== accept (mcp 2.3.0)
  prompt: [prod] delete_service: permanently delete a service (irreversible) (tier L2).
          Arguments: {"name": "api"}
          Dry-run preview: would delete api
          Confirm to execute for real. Idempotency key: b927e04769934b77832985570449e52b
  retry : [{"requestState": "al1.eyJwIjoi...", "inputResponses": {"airlock-confirm": {"action": "accept", "content": {"confirm": true}}}}]
  result: is_error=False rule_id=tier.L2.confirmed text='DELETED api'
  audit : [('tier.L2.confirm', True), ('tier.L2.confirmed', False)]
  [ok] callback got the dry-run description once
  [ok] inputResponses sent back with accept
  [ok] call ran
  [ok] audit has tier.L2.confirmed

== decline (mcp 2.3.0)
  prompt: [prod] delete_service: permanently delete a service (irreversible) (tier L2).
          Arguments: {"name": "api"}
          Dry-run preview: would delete api
          Confirm to execute for real. Idempotency key: 7a56710c2f5f4f98b6a46875686bf038
  retry : [{"requestState": "al1.eyJwIjoi...", "inputResponses": {"airlock-confirm": {"action": "decline"}}}]
  result: is_error=True rule_id=mrtr.declined text='airlock: denied (mrtr.declined)'
  audit : [('tier.L2.confirm', True), ('mrtr.declined', None)]
  [ok] callback got the prompt once
  [ok] inputResponses sent back with decline
  [ok] decline came back as a tool error
  [ok] audit has mrtr.declined, no confirmed run

== no elicitation_callback (mcp 2.3.0)
  retry : none sent
  raised: MCPError: Elicitation not supported
  audit : [('tier.L2.confirm', True)]
  [ok] call raised MCPError
  [ok] no retry was sent
  [ok] nothing ran for real

all expectations held
```

### Adding a row

Contributions are welcome. To test a client:

1. Unset `AIRLOCK_APPROVAL_WEBHOOK` and every other `AIRLOCK_*` variable in the shell first (a
   webhook implies `oob` mode, where an accept in the client approves nothing), then run
   `uv run python -m tests.fake_upstream` and
   `AIRLOCK_TRUST_PRINCIPAL_HEADER=1 uv run mcp-airlock --policy policy.example.yaml --upstream http://127.0.0.1:9001/mcp --env prod`.
2. Register the proxy as shown above, ask the client to call `delete_service` with name
   `api`, and answer accept once. Repeat and answer decline.
3. Check `uv run airlock-audit query --jsonl audit.jsonl --tool delete_service --phase outcome`.
   Expect `tier.L2.confirm` then `tier.L2.confirmed` for accept, or `mrtr.declined` for decline.
4. Open a PR with the client version, the date, and a screenshot or transcript.

## One proxy per server

Run one `mcp-airlock` per upstream, each with its own policy file, and register each as a
separate server in the client. The policy is a flat allowlist for one server's tool names;
mixing servers behind one proxy would mean one policy for both catalogs.
