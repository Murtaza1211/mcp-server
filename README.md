# mcp-server

An [MCP](https://modelcontextprotocol.io) server for inspecting IBM Liberty /
WebSphere-style application servers over SSH — reading config with secrets
redacted, checking whether an app is actually up, and searching its logs.

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

### `list_logs`

Connects over SSH and enumerates every file under
`<deployment_directory>/<application>/logs/` — Liberty's own `messages.log`,
`console.log`, `trace.log`, `ffdc/*`, plus whatever an application itself
writes into subdirectories there. Meant to be called before `analyze_logs`
so an LLM can pick which files are actually relevant instead of blindly
grepping everything (`trace.log` especially can be huge).

**Arguments**

| Name | Type | Description |
|---|---|---|
| `server_ip` | string | Hostname or IP address of the server to connect to over SSH. |
| `os_user` | string | SSH username to authenticate as. |
| `ssh_key` | string | Path to the private key file (on the machine running this MCP server) used for authentication. |
| `deployment_directory` | string | Base deployment directory containing the application folder. |
| `application` | string | Name of the application subfolder whose `logs/` directory to list. |

**Example result shape**

```json
{
  "server": "10.0.1.25",
  "logs_directory": "/opt/liberty/deployments/myapp/logs",
  "files": [
    { "path": "messages.log", "size_bytes": 827, "modified": "2026-07-28T00:45:10+00:00", "category": "liberty_core" },
    { "path": "trace.log", "size_bytes": 111, "modified": "2026-07-28T00:10:00+00:00", "category": "liberty_core" },
    { "path": "ffdc/com.ibm.ws.webcontainer_exception_...txt", "size_bytes": 178, "modified": "2026-07-28T00:15:32+00:00", "category": "ffdc" },
    { "path": "myapplogs/app-2026-07-28.log", "size_bytes": 174, "modified": "2026-07-28T00:50:00+00:00", "category": "app_or_other" }
  ]
}
```

### `analyze_logs`

Connects over SSH and greps the app's logs for given strings/exception
names, returning matches with surrounding context.

**Arguments**

| Name | Type | Description |
|---|---|---|
| `server_ip` | string | Hostname or IP address of the server to connect to over SSH. |
| `os_user` | string | SSH username to authenticate as. |
| `ssh_key` | string | Path to the private key file (on the machine running this MCP server) used for authentication. |
| `deployment_directory` | string | Base deployment directory containing the application folder. |
| `application` | string | Name of the application subfolder whose `logs/` directory to search. |
| `search` | list of strings | Strings or exception names to search for (case-insensitive, literal match). |
| `start_time` | string, optional | ISO-8601 timestamp; matches before this are excluded when a timestamp is detected. |
| `end_time` | string, optional | ISO-8601 timestamp; matches after this are excluded when a timestamp is detected. |
| `log_files` | list of strings, optional | Paths relative to `logs/`, as returned by `list_logs`, to restrict the search to. If omitted, every discovered file is searched, skipping any over ~25MB. |

**What it does**

1. If `log_files` isn't given, discovers every file under `logs/` (capped at
   300 files) and skips any over ~25MB — those get reported back under
   `skipped_files` rather than silently ignored, so the LLM knows to pass
   them explicitly via `log_files` if they're actually needed.
2. If `start_time` is given, skips whole files whose last-modified time
   predates it (log files are append-only, so an untouched-since-`start_time`
   file can't contain anything newer).
3. Runs `grep -n -i -a -F -C 2` per file for the given terms and groups
   matches into context blocks.
4. For each block, tries to find a timestamp — Liberty's basic format
   (`[7/28/26 0:15:32:123 UTC]`), Liberty's JSON format (`"ibm_datetime"`),
   or generic ISO-8601 for arbitrary app logs — anchored on the actually
   matched line (not just the first line of the context block). If found and
   outside `[start_time, end_time]`, the block is dropped; **if no timestamp
   can be parsed, the block is kept rather than silently discarded** — stack
   traces and multi-line messages don't repeat their header's timestamp, and
   hiding potentially-relevant lines is worse than including a few extra ones.

**Example result shape**

```json
{
  "server": "10.0.1.25",
  "logs_directory": "/opt/liberty/deployments/myapp/logs",
  "search": ["NullPointerException"],
  "results": [
    {
      "file": "messages.log",
      "timestamp": "2026-07-28T00:15:32.123000",
      "lines": [
        "2-[7/28/26 0:15:32:123 UTC] ... E   SRVE0777E: Exception thrown by application class",
        "3:java.lang.NullPointerException: Cannot invoke method on null object",
        "4-\tat com.example.myapp.Service.process(Service.java:42)"
      ]
    }
  ],
  "truncated": false,
  "skipped_files": []
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
`read_config`, `health_check`, `list_logs`, and `analyze_logs` as discovered
tools.

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
  logs.py           list_logs / analyze_logs: log discovery + grep with time filtering
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

uv run python -c "
from mcp_server.logs import list_logs, analyze_logs
import json
print(json.dumps(list_logs('10.0.1.25', 'appuser', '~/.ssh/id_rsa', '/opt/liberty/deployments', 'myapp'), indent=2))
print(json.dumps(analyze_logs('10.0.1.25', 'appuser', '~/.ssh/id_rsa', '/opt/liberty/deployments', 'myapp', ['NullPointerException']), indent=2))
"
```
