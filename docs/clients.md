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

Only do that on a machine where nobody else can reach port 9000. Anywhere shared, leave the
variable unset and give the client a bearer JWT instead (`AIRLOCK_JWT_SECRET` or
`AIRLOCK_JWKS_URL` on the proxy side, see the README).

## Claude Code

One command, user scope:

```
claude mcp add --transport http github-airlocked http://127.0.0.1:9000/mcp \
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
proxy only returns tools that are in the policy, so a tool the agent "cannot see" is a
policy question, not a connection problem.

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
  with the state; the proxy then runs it for real, once.

That last point is the one to check before relying on `L2`. Call an `L2` tool from the
client and see whether you get asked. If the client ignores `input_required`, the model
just sees an unusual result and cannot complete the call; in that case keep such tools at
`L3` with a small blast radius, or at `L1`, until the client catches up. Out-of-band
approval through Slack or Telegram does not change this: the agent still has to repeat the
call with `requestState` after the button is pressed.

## One proxy per server

Run one `mcp-airlock` per upstream, each with its own policy file, and register each as a
separate server in the client. The policy is a flat allowlist for one server's tool names;
mixing servers behind one proxy would mean one policy for both catalogs.
