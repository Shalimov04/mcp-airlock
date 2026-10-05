# Security

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: the **Security** tab of this repository, then
**Report a vulnerability**. That keeps the report private until there is a fix. Please do not
open a public issue for something exploitable.

This is a one-person project, so promise nothing more than this: I will acknowledge a report
within a week, tell you whether I think it is a real problem and what I intend to do, and
credit you in the release notes unless you would rather I didn't. If a fix is needed it lands
in a patch release on PyPI and ghcr.

Supported: the latest released version. There is no backporting to older tags yet.

## What counts as a vulnerability here

The proxy exists to keep an agent from doing things on its own, so anything that gets a call
past the policy is in scope:

* A `tools/call` that reaches the upstream without matching an allowlist entry.
* A gated call that executes without the tier's dry run or confirmation.
* A confirmation token (`requestState`) that can be forged, replayed, or reused for a
  different principal, tool, argument set, environment or upstream.
* An approve link that approves something other than the call it was issued for, or that a
  `GET` alone can trigger.
* A principal resolved from anywhere other than a verified token or a trusted gateway header,
  in particular from the request body or from `_meta`.
* A `where` rule or a blast-radius count that an argument encoding gets around.
* A pinned tool whose definition changed and that `tools/list` still returns.
* Secrets reaching the audit log, the approval message, the dry-run preview, the spans or the
  process log unredacted. Spans and log lines must never carry arguments, webhook URLs or DSNs.
* An audit record that can be edited, deleted or reordered without `airlock-audit verify`
  noticing, except for the cases listed below.
* Anything in a tool result or a tool description that changes a verdict. Tool output is data
  here and must stay data.

## What is known and not a vulnerability

These are documented behaviours, not bugs. A report about one of them will get a link back to
this section.

* **The approve URL is a capability URL.** Anyone holding the link can press the button. It is
  meant to sit behind your SSO proxy or VPN; the README says so.
* **`AIRLOCK_TRUST_PRINCIPAL_HEADER=1` trusts `X-Airlock-Principal`.** That is the point of the
  flag. It is off by default and only safe behind a gateway that sets the header itself and
  strips it from clients.
* **Injection marking is regex and it marks, it never blocks.** That holds for tool results and
  for the titles and descriptions in `tools/list`. It will miss things and it will occasionally
  flag a normal sentence. A missed pattern is a feature request, not a vulnerability.
* **Pins trust the server at pin time.** `airlock-policy pin` records whatever the server lists.
  A description that was already poisoned when it was pinned stays pinned; review the catalog
  before pinning it.
* **Forced dry run trusts the tool.** The proxy checks that a tool declares a `dry_run`
  argument; it cannot check that the implementation honours it. Test that yourself before
  putting a tool at `L1` or `L2`.
* **Blast radius counts what the arguments show.** A tool whose fan-out is invisible in its
  arguments cannot be measured here.
* **Without `AIRLOCK_STORE_DSN` the state is per process.** Two replicas without a shared
  store can each burn their own copy of a confirmation key. Set the DSN if you run more than
  one.
* **In `inband` approval mode, whoever sends `inputResponses` confirms.** Without a webhook the
  mode is `inband`, and the client's accept is the approval; making sure only a person sends
  it is the client's job.
* **The audit hash chain has no external anchor.** A truncated tail, a re-hashed newest record
  and a file rewritten from start to end with a consistent chain are not detected unless you
  anchor the last hash somewhere else. The README says which breaks `verify` does catch.
* **Whoever can read the Helm release's Secret can mint any principal.** The generated
  `AIRLOCK_JWT_SECRET` is an ordinary Kubernetes Secret. Use JWKS or your own `existingSecret`
  when that is too broad.
* **Denial of service by an authenticated principal.** There is no rate limit on prompting; an
  agent that keeps re-sending an `L2` call gets a new prompt each time.

If you think one of these is worse than I have described it, say so in the report. I would
rather hear the argument than have the same thing rediscovered quietly.
