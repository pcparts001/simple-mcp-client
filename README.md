# simple-mcp-client (mcpTester)

A standalone CLI tool **`mcpTester.py`** for verifying that an MCP Server works correctly.

## Overview

`mcpTester.py` is a CLI script to quickly verify an implemented MCP Server from another environment.

- **Runs on the standard library only** (no LLM or function calling)
- Communicates with the MCP Server via JSON-RPC and sequentially verifies `initialize` / `tools/list` / `tools/call` / `ping` / `prompts/list` / `resources/list`
- Optional OAuth 2.1 + PKCE (Authorization Code Flow) support
  - When `oauth.enabled=true`, it works with the IdP to obtain a Bearer token and attaches it to all requests
  - When disabled, it runs unauthenticated
- Supports the following specs
  - RFC 9728 (automatic IdP discovery via Protected Resource Metadata)
  - RFC 7591 (Dynamic Client Registration)
  - RFC 8707 (resource parameter)

## Prerequisites

- Python 3 (standard library only; no extra packages required)

## Setup

### Create the config file

Copy `mcp_tester_config.json.example` to `mcp_tester_config.json` and edit it for your environment.

```bash
cp mcp_tester_config.json.example mcp_tester_config.json
```

**To test without authentication** (no OAuth), simply set `enabled` to `false`.

```json
{
  "oauth": {
    "enabled": false
  }
}
```

**To use OAuth**, set `issuer` / `client_id` / `client_secret` / `scope`, etc. to your IdP's values (see the comments in the example file for details).

> ⚠️ **Note**: `mcp_tester_config.json` may contain secrets and is excluded by `.gitignore`. **Never commit it.**

## Usage

```bash
# Check the default (http://localhost:9000)
python3 mcpTester.py

# Specify the URL explicitly
python3 mcpTester.py http://localhost:9000
python3 mcpTester.py http://192.168.1.10:9000

# Specify via environment variable
MCP_SERVER_URL=http://host:9000 python3 mcpTester.py
```

## Verification steps

1. **OAuth authentication** (only when `oauth.enabled=true`) — obtains an access token via the Authorization Code Flow + PKCE
2. **Health Check** (GET)
3. **`initialize`**
4. **`tools/list`**
5. **`tools/call`** — actually invokes `get_test_string` / `echo` / `check_maintenance` if they exist on the server
6. **Others** — `ping` / `prompts/list` / `resources/list`

## Exit codes

| Code | Meaning |
|:---:|:---|
| `0` | All steps passed |
| `1` | Any step failed |

## Directory layout

```
simple-mcp-client/
├── mcpTester.py                     # main script (test MCP Client)
├── mcp_tester_config.json.example   # config template
├── requirements.txt                 # (no dependencies; runs on the standard library)
├── .gitignore
└── README.md
```
