# mcp-server

An [MCP](https://modelcontextprotocol.io) server for inspecting IBM Liberty /
WebSphere-style application servers over SSH — reading config with secrets
redacted, checking whether an app is actually up, searching its logs, and
checking outward connectivity and on-box resource pressure for triage.

## Tools

### `read_config`

Connects to a remote server over SSH and returns its application config as
sanitized text.

**Arguments**

| Name                   | Type   | Description                                                                                    |
| ---------------------- | ------ | ------------------------------------------------------------------------------------------------ |
| `server_ip`            | string | Hostname or IP address of the server to connect to over SSH.                                   |
| `os_user`              | string | SSH username to authenticate as.                                                                |
| `ssh_key`              | string | Path to the private key file (on the machine running this MCP server) used for authentication. |
| `deployment_directory` | string | Base deployment directory containing the application folder.                                   |
| `application`          | string | Name of the application subfolder to read config from.                                         |

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

| Name          | Type    | Description                                                                                    |
| ------------- | ------- | ------------------------------------------------------------------------------------------------ |
| `server_ip`   | string  | Hostname or IP address of the server to connect to over SSH.                                   |
| `os_user`     | string  | SSH username to authenticate as.                                                                |
| `ssh_key`     | string  | Path to the private key file (on the machine running this MCP server) used for authentication. |
| `port`        | integer | Local port the application listens on.                                                          |
| `uri`         | string  | URI path to request for the HTTP health check (e.g. `/health`).                                |
| `application` | string  | Application/server name to look for among running processes.                                    |

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
`<deployment_directory>/<application>/logs/` — Liberty's own
`messages.log`, `console.log`, `trace.log`, `ffdc/*`, plus whatever an
application itself writes into subdirectories there. Meant to be called
before `analyze_logs` so an LLM can pick which files are actually relevant
instead of blindly grepping everything (`trace.log` especially can be huge).

**Arguments**

| Name                   | Type   | Description                                                                                    |
| ---------------------- | ------ | ------------------------------------------------------------------------------------------------ |
| `server_ip`            | string | Hostname or IP address of the server to connect to over SSH.                                   |
| `os_user`              | string | SSH username to authenticate as.                                                                |
| `ssh_key`              | string | Path to the private key file (on the machine running this MCP server) used for authentication. |
| `deployment_directory` | string | Base deployment directory containing the application folder.                                   |
| `application`          | string | Name of the application subfolder whose `logs/` directory to list.                              |

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

| Name                   | Type                      | Description                                                                                                                                                |
| ---------------------- | ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `server_ip`            | string                    | Hostname or IP address of the server to connect to over SSH.                                                                                              |
| `os_user`              | string                    | SSH username to authenticate as.                                                                                                                          |
| `ssh_key`              | string                    | Path to the private key file (on the machine running this MCP server) used for authentication.                                                            |
| `deployment_directory` | string                    | Base deployment directory containing the application folder.                                                                                              |
| `application`          | string                    | Name of the application subfolder whose `logs/` directory to search.                                                                                      |
| `search`               | list of strings           | Strings or exception names to search for (case-insensitive, literal match).                                                                               |
| `start_time`           | string, optional          | ISO-8601 timestamp; matches before this are excluded when a timestamp is detected.                                                                        |
| `end_time`             | string, optional          | ISO-8601 timestamp; matches after this are excluded when a timestamp is detected.                                                                         |
| `log_files`            | list of strings, optional | Paths relative to `logs/`, as returned by `list_logs`, to restrict the search to. If omitted, every discovered file is searched, skipping any over ~25MB. |

**What it does**

1. If `log_files` isn't given, discovers every file under `logs/` (capped at
   300 files) and skips any over ~25MB — those get reported back under
   `skipped_files` rather than silently ignored, so the LLM knows to pass
   them explicitly via `log_files` if they're actually needed.
2. If `start_time` is given, skips whole files whose last-modified time
   predates it (log files are append-only, so an untouched-since-`start_time`
   file can't contain anything newer).
3. Greps the target files for the given terms and groups matches into
   context blocks. **Files are searched in batches of up to 50 per SSH exec
   call** (one remote command greps every file in the batch, with an
   internal marker separating each file's output) rather than one exec call
   per file — this cuts SSH round-trips from roughly *N+2* down to roughly
   *⌈N/50⌉+2* for a directory of *N* log files, which matters most for the
   unscoped default search across many files.
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

### `check_connectivity`

Connects over SSH and, for each `host:port` dependency target, resolves DNS
and probes TCP reachability — the practical, non-root substitute for a
firewall-rule dump (inspecting actual `iptables`/`firewalld` rules would
need privileges these deployments don't have; a connect attempt reports
almost everything a rule dump would for triage purposes: reachable, refused,
or timed out).

**Arguments**

| Name        | Type             | Description                                                                                                     |
| ----------- | ---------------- | ------------------------------------------------------------------------------------------------------------------ |
| `server_ip` | string           | Hostname or IP address of the server to connect to over SSH.                                                    |
| `os_user`   | string           | SSH username to authenticate as.                                                                                |
| `ssh_key`   | string           | Path to the private key file (on the machine running this MCP server) used for authentication.                 |
| `targets`   | list of strings  | `"host:port"` entries for the dependencies to check (e.g. DB or LDAP hosts referenced in the app's config, as returned by `read_config`). Max 50 per call. |

**What it does**

1. Targets are supplied explicitly by the caller rather than auto-discovered
   from config — parsing every hostname out of `server.xml`/datasource
   URLs/JVM options reliably would need meaningfully more logic (variable
   resolution, JDBC/endpoint URL parsing), and a *missed* dependency here is
   worse than a missed log line: overlooking the one host that's actually
   down during an incident is worse than a slightly less convenient tool.
2. For each target, resolves DNS via `getent hosts` (no root required, no
   dependency on `dig`/`nslookup` being installed) and filters to IPv4
   addresses only (these deployments are IPv4-only).
3. **If a hostname resolves to more than one IP** — common for active-active
   DB replicas, LDAP pairs, or load-balanced backends — **every address is
   probed individually**, never just the hostname. Letting the shell resolve
   the hostname itself would silently pick one address and could report a
   dependency as fully healthy while one backend is actually down behind a
   healthy one.
4. Each address gets a TCP connect attempt (`/dev/tcp/<ip>/<port>` via bash,
   no `nc`/`telnet` dependency) with a 3-second timeout, distinguishing
   `connected` / `refused` / `timeout` / `unreachable`.
5. All targets are checked within a single SSH exec call (same round-trip
   reasoning as the `analyze_logs` batching).

Reports two rollup fields per target because they answer different
questions: **`reachable`** (true if *at least one* resolved address answers
— "can the app get through at all") and **`fully_reachable`** (true only if
*every* resolved address answers — "is a backend silently down behind a
healthy one").

**Example result shape**

```json
{
  "server": "10.0.1.25",
  "results": [
    {
      "target": "db-primary.internal:5432",
      "resolved": true,
      "addresses": [
        { "ip": "10.0.2.10", "reachable": true, "detail": "connected" },
        { "ip": "10.0.2.11", "reachable": false, "detail": "refused" }
      ],
      "reachable": true,
      "fully_reachable": false
    },
    {
      "target": "ldap.corp.example:636",
      "resolved": false,
      "addresses": [],
      "reachable": false,
      "fully_reachable": false
    }
  ],
  "malformed_targets": []
}
```

### `check_resources`

Connects over SSH and checks disk, memory, and file-descriptor pressure on
the box — root-cause categories that often produce log lines which look
like an unrelated app bug (a `NullPointerException` three layers deep in
application code can be the downstream symptom of a full disk or an
exhausted fd table).

**Arguments**

| Name                   | Type   | Description                                                                                                                        |
| ---------------------- | ------ | -------------------------------------------------------------------------------------------------------------------------------------- |
| `server_ip`            | string | Hostname or IP address of the server to connect to over SSH.                                                                       |
| `os_user`              | string | SSH username to authenticate as.                                                                                                    |
| `ssh_key`              | string | Path to the private key file (on the machine running this MCP server) used for authentication.                                     |
| `deployment_directory` | string | Base deployment directory containing the application folder.                                                                        |
| `application`          | string | Name of the application subfolder (also used to find its process among running processes, same `ps -ef` approach as `health_check`). |

**What it does**

1. **Disk** — checked for exactly three filesystems, not every mounted one:
   the filesystem holding `<deployment_directory>/<application>` (where
   logs/FFDC/work files actually get written), `/tmp` (where the JVM writes
   temp files by default), and `/` (root — a cheap sanity check if it's a
   distinct filesystem from the other two). Enumerating every mount would
   add noise from filesystems irrelevant to this app; if two of the three
   checks land on the same filesystem, that's visible from matching
   `mounted_on` values rather than hidden. Each check reports both **space**
   (`df -Pk`) and **inode** (`df -Pi`) usage — a full inode table can block
   writes well before the disk is out of bytes (FFDC directories dump one
   file per failure and can exhaust inodes long before space runs low).
2. **Memory** — `free -m` (falling back to `/proc/meminfo` if `free` isn't
   present), reporting total/used/free/available plus swap.
3. **Process** — finds the app's PID via the same `ps -ef` grep
   `health_check` uses, then reports its open file descriptor count
   (`/proc/<pid>/fd`) against its ulimit (`/proc/<pid>/limits`) — "too many
   open files" is one of the most common real-world Liberty production
   failures.
4. All of the above runs within a single SSH exec call.

**Example result shape**

```json
{
  "server": "10.0.1.25",
  "deployment_path_checked": "/opt/liberty/deployments/myapp",
  "disk": {
    "deployment": {
      "available": true,
      "filesystem": "/dev/sda1",
      "mounted_on": "/opt",
      "total_mb": 40968.0,
      "used_mb": 12065.0,
      "available_mb": 26100.0,
      "used_pct": 32,
      "total_inodes": 2621440,
      "used_inodes": 123456,
      "available_inodes": 2497984,
      "inode_used_pct": 5
    },
    "tmp": { "available": true, "mounted_on": "/", "used_pct": 47, "inode_used_pct": 2 },
    "root": { "available": true, "mounted_on": "/", "used_pct": 47, "inode_used_pct": 2 }
  },
  "memory": {
    "total_mb": 7982,
    "used_mb": 1234,
    "free_mb": 2048,
    "available_mb": 6500,
    "swap_total_mb": 2047,
    "swap_used_mb": 0,
    "swap_free_mb": 2047,
    "source": "free"
  },
  "process": {
    "found": true,
    "pid": "25579",
    "open_file_descriptors": 412,
    "fd_soft_limit": 4096,
    "fd_hard_limit": 4096,
    "fd_usage_pct": 10.1
  }
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
`read_config`, `health_check`, `list_logs`, `analyze_logs`,
`check_connectivity`, and `check_resources` as discovered tools.

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
  logs.py           list_logs / analyze_logs: log discovery + batched grep with time filtering
  connectivity.py   check_connectivity: DNS resolution (multi-IP aware) + TCP reachability probes
  resources.py      check_resources: disk/inode, memory/swap, and fd-vs-ulimit checks
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

uv run python -c "
from mcp_server.connectivity import check_connectivity
import json
print(json.dumps(check_connectivity('10.0.1.25', 'appuser', '~/.ssh/id_rsa', ['db-primary.internal:5432', 'ldap.corp.example:636']), indent=2))
"

uv run python -c "
from mcp_server.resources import check_resources
import json
print(json.dumps(check_resources('10.0.1.25', 'appuser', '~/.ssh/id_rsa', '/opt/liberty/deployments', 'myapp'), indent=2))
"
```
