# Example policies for real MCP servers

| File | Upstream | Environments |
|------|----------|--------------|
| `github.yaml` | [github/github-mcp-server](https://github.com/github/github-mcp-server) | `dev` (sandbox org), `prod` |
| `grafana.yaml` | [grafana/mcp-grafana](https://github.com/grafana/mcp-grafana) | `dev`, `staging`, `prod` |
| `kubernetes.yaml` | [containers/kubernetes-mcp-server](https://github.com/containers/kubernetes-mcp-server) | `dev`, `staging`, `prod` |

Reads are `L0` everywhere; comments/annotations/incidents are `L3` in dev and `L2` in prod; file writes,
merges, deletes and anything that pages a human are `L2` everywhere with a one-object blast radius. Tools not
listed are denied. Each file's header says which tools were left out and why, and the commit the catalog was checked against.

Run airlock in front of a server that speaks Streamable HTTP (each server documents its own `--port`/`--transport` flag):

```bash
uv run mcp-airlock --policy examples/policies/kubernetes.yaml --env prod \
    --upstream http://127.0.0.1:8080/mcp --audit audit.jsonl
```

Most of these write tools have no dry_run argument. Through mcp-airlock that means: L1 is denied, L2 prompts the human
WITHOUT a dry-run preview, L3 executes as sent. Verify against the live catalog with
`airlock-policy diff <file> --upstream <url>`. `tests/test_example_policies.py` only checks that the files parse and
follow the tiering rules above; it cannot check the upstream still exposes these names.
