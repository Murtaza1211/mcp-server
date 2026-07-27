# mcp-server

An [MCP](https://modelcontextprotocol.io) server for inspecting IBM Liberty /
WebSphere-style application servers over SSH — reading config with secrets
redacted, and checking whether an app is actually up.

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

### `health_check`

Connects to a remote server over SSH and reports whether an IBM Liberty app
is healthy: an HTTP probe plus a process check. Built for locked-down
targets — assumes a **non-root** SSH user with **no access to root-owned
paths**, and **no JDK installed**, so it never shells out to `jps`, `jcmd`,
or `bin/server status`.

**Arguments**

| Name | Type | Description |
|---|---|---|
| `server_ip` | string | Hostname or IP address of the server to connect to over SSH. |
| `os_user` | string | SSH username to authenticate as. |
| `ssh_key` | string | Path to the private key file (on the machine running this MCP server) used for authentication. |
| `port` | integer | Local port the application listens on. |
| `uri` | string | URI path to request for the HTTP health check (e.g. `/health`). |
| `application` | string | Application/server name to look for among running processes. |

**What it does**

1. Opens one SSH session to `server_ip` as `os_user` and runs two small
   shell scripts on the remote host (no local files needed, no `sudo`):
   - **HTTP check**: requests `http://127.0.0.1:<port><uri>` using whichever
     of `curl`, `wget`, or `python3` is present on the target, in that order.
     If none are available it reports that rather than guessing.
   - **Process check**: greps `ps -ef` for a line containing both `java` and
     `application`, since Liberty runs as a plain JVM process and there's no
     JDK on the box to ask it directly.
2. Returns HTTP reachability + status code + a healthy/unhealthy verdict
   (2xx/3xx counts as healthy), and process running/not-running + PID.

**Example result shape**

```json
{
  "server": "10.0.1.25",
  "application": "myapp",
  "http": { "reachable": true, "status_code": 200, "healthy": true, "detail": "HTTP 200" },
  "process": { "running": true, "pid": "25579", "detail": "501 25579 ... java ... myapp ..." }
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
`read_config` and `health_check` as discovered tools.

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
  ssh.py            Shared SSH connection helper (used by every tool)
  config_reader.py  read_config: file discovery over SFTP, path-traversal guard
  health_check.py   health_check: HTTP probe + process check over SSH exec
  sanitize.py       Regex-based secret redaction
```

## Development

```bash
uv run python -c "
from mcp_server.config_reader import read_config
import json
print(json.dumps(read_config('10.0.1.25', 'appuser', '~/.ssh/id_rsa', '/opt/liberty/deployments', 'myapp'), indent=2))
"

uv run python -c "
from mcp_server.health_check import check_health
import json
print(json.dumps(check_health('10.0.1.25', 'appuser', '~/.ssh/id_rsa', 9080, '/health', 'myapp'), indent=2))
"
```
