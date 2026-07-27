# mcp-server

An [MCP](https://modelcontextprotocol.io) server for reading Liberty/WebSphere-style
application server configuration over SSH, with secrets automatically redacted
before the content ever reaches an LLM.

## Tools

### `read_config`

Connects to a remote server over SSH and returns its application config as
sanitized text.

**Arguments**

| Name | Type | Description |
|---|---|---|
| `server_ip` | string | Hostname or IP address of the server to connect to over SSH. |
| `os_user` | string | SSH username to authenticate as. |
| `ssh_key` | string | Path to the private key file (on the machine running this MCP server) used for authentication. |
| `deployment_directory` | string | Base deployment directory containing the application folder. |
| `application` | string | Name of the application subfolder to read config from. |

**What it does**

1. Opens an SFTP session to `server_ip` as `os_user`, authenticating with
   `ssh_key`. Strict host key checking is disabled (`StrictHostKeyChecking=no`
   equivalent) — unknown hosts are auto-accepted rather than requiring a
   `known_hosts` entry. This trades off protection against man-in-the-middle
   attacks for not having to pre-seed `known_hosts` for every target server.
2. Looks in `<deployment_directory>/<application>/` on that server.
3. Reads `server.xml`.
4. Scans `server.xml` for `<include location="...">` references and any
   `*.properties` file references, and reads those too.
5. Always also reads (if present): `jvm.options`, `server.env`,
   `bootstrap.properties`.
6. Redacts values associated with sensitive keys — `password`, `secret`,
   `token`, `apikey`, `credential`, etc. — in both `key=value` style
   (properties files, `.env`, `-D` JVM options) and XML attribute style,
   including Liberty's `<variable name="db.password" value="..."/>` pattern
   where the keyword and the secret live in separate attributes.
7. Returns a single JSON object with the sanitized content of every file
   found (and a not-found/error note for anything missing).

References that would resolve outside the application directory (e.g. path
traversal via `../../`) or that depend on an unresolved `${variable}` are
skipped rather than followed.

**Note:** only the SSH key *path* is ever passed to the tool — key material
itself never flows through the LLM or tool-call history.

**Example result shape**

```json
{
  "server": "10.0.1.25",
  "application_directory": "/opt/liberty/deployments/myapp",
  "files": [
    { "path": "server.xml", "found": true, "content": "..." },
    { "path": "jvm.options", "found": true, "content": "..." },
    { "path": "server.env", "found": true, "content": "..." },
    { "path": "bootstrap.properties", "found": true, "content": "..." },
    { "path": "vars/extra.properties", "found": true, "content": "..." }
  ]
}
```

## Setup

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/Murtaza1211/mcp-server.git
cd mcp-server
uv sync
```

That installs the `mcp` SDK and registers the `mcp-server` console script
(`uv run mcp-server`), which starts the server over stdio.

## Connecting to an MCP client

Any MCP client that supports stdio servers can run this directly. The
general pattern is:

- **command**: `uv`
- **args**: `["--directory", "/absolute/path/to/mcp-server", "run", "mcp-server"]`

### Hermes Agent

Add to `~/.hermes/config.yaml`:

```yaml
mcp_servers:
  server-config-reader:
    command: /absolute/path/to/uv
    args: ["--directory", "/absolute/path/to/mcp-server", "run", "mcp-server"]
```

Then verify:

```bash
hermes mcp list
hermes mcp test server-config-reader
```

`hermes mcp test` should report a successful connection and list
`read_config` as a discovered tool.

### Claude Desktop / other MCP clients

Add an equivalent entry to the client's MCP server config, e.g. for Claude
Desktop's `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "server-config-reader": {
      "command": "uv",
      "args": ["--directory", "/absolute/path/to/mcp-server", "run", "mcp-server"]
    }
  }
}
```

## Project layout

```
src/mcp_server/
  server.py         MCP tool registration (FastMCP)
  config_reader.py  Directory walk, file discovery, path-traversal guard
  sanitize.py        Regex-based secret redaction
```

## Development

```bash
uv run python -c "
from mcp_server.config_reader import read_config
import json
print(json.dumps(read_config('/path/to/deployments', 'myapp'), indent=2))
"
```
