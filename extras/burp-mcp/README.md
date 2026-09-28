# Burp Suite MCP — Unified Server

Bridges Burp Suite into MCP so the pipeline (and any MCP client) can drive Burp directly:
proxy traffic, Repeater, Intruder, Scanner, Collaborator, sitemap and cookies.

Two components (kept from the working setup):

| File | Role |
|------|------|
| `burp_unified_mcp.py` | Main MCP server — merges **52 BurpMCP Jar tools** (SSE `:8181`) with **REST API tools** (`:1337`), falls back to REST-only when SSE is down |
| `stdio-bridge.py` | STDIO ↔ SSE bridge for clients that only support STDIO |

## Requirements

- Burp Suite running locally
- BurpMCP extension Jar (`BurpMCP-1.1.0.jar`, Extender → Add) exposing SSE on `:8181`
- Burp REST API extension enabled on `:1337` (User options → REST API)
- `pip install mcp requests`

## Environment

| Variable | Default | Purpose |
|----------|---------|---------|
| `BURP_SSE_URL` | `http://localhost:8181/mcp/sse` | BurpMCP Jar tools (52) |
| `BURP_REST_URL` | `http://127.0.0.1:1337` | Burp REST API tools (fallback) |
| `BURP_PROXY` | `http://127.0.0.1:8080` | proxy used for outbound requests |

## opencode config

Add to `~/.config/opencode/opencode.json` under `mcp`:

```jsonc
"burp": {
  "type": "local",
  "command": ["/usr/bin/python3", "/path/to/burp-mcp/burp_unified_mcp.py"],
  "enabled": true,
  "environment": {
    "BURP_SSE_URL": "http://localhost:8181/mcp/sse",
    "BURP_REST_URL": "http://127.0.0.1:1337",
    "BURP_PROXY": "http://127.0.0.1:8080"
  }
}
```

## Cline config

Add to `~/.cline/data/settings/cline_mcp_settings.json`:

```jsonc
"burp": {
  "command": "/usr/bin/python3",
  "args": ["/path/to/burp-mcp/burp_unified_mcp.py"],
  "env": {
    "BURP_SSE_URL": "http://localhost:8181/mcp/sse",
    "BURP_REST_URL": "http://127.0.0.1:1337",
    "BURP_PROXY": "http://127.0.0.1:8080"
  },
  "disabled": false,
  "autoApprove": []
}
```

## Usage in this pipeline

- **Phase 06** routes the emulator's traffic through the Burp proxy (`proxy.host`/`proxy.port`
  in `config/target.yaml`) and extracts endpoints into `traffic/api_endpoints.txt`.
- Those endpoints are then attacked in Burp (Repeater / Intruder / Scanner) via the MCP tools.
- `./run.sh vapt_handoff` copies discovered endpoints + secrets for the web VAPT pipeline.